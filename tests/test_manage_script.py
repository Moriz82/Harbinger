import os
from pathlib import Path
import shutil
import subprocess


def test_host_side_state_change_refuses_running_service(tmp_path):
    project = tmp_path / 'project'
    project.mkdir()
    shutil.copy2(Path(__file__).parents[1] / 'manage.sh', project / 'manage.sh')
    fake_bin = tmp_path / 'bin'
    fake_bin.mkdir()
    docker = fake_bin / 'docker'
    docker.write_text(
        '#!/bin/sh\n'
        'case " $* " in\n'
        '  *" compose version "*) exit 0 ;;\n'
        '  *" ps --status running -q "*) echo synthetic-container-id; exit 0 ;;\n'
        'esac\n'
        'exit 99\n'
    )
    docker.chmod(0o700)
    result = subprocess.run(
        ['bash', str(project / 'manage.sh'), 'add-user', 'synthetic-user', 'tester'],
        text=True,
        capture_output=True,
        env={**os.environ, 'PATH': str(fake_bin) + os.pathsep + os.environ['PATH']},
    )
    assert result.returncode == 1
    assert result.stdout == ''
    assert 'Stop Harbinger before a host-side state change.' in result.stderr
    assert not (project / 'state').exists()


def test_password_commands_keep_an_interactive_terminal():
    script = (Path(__file__).parents[1] / 'manage.sh').read_text()
    assert 'run_cli_prompt() { ensure_team_network; compose run --rm --no-deps app ' in script
    assert 'run_cli_prompt add-user "$user" --role "$DEFAULT_ROLE"' in script
    assert 'run_cli_prompt add-user "$2" --role "$3"' in script


def test_workspace_directories_must_match_the_configured_runtime_owner():
    script = (Path(__file__).parents[1] / 'manage.sh').read_text()
    prepare = script.split('prepare_dirs() {', 1)[1].split('\n}', 1)[0]
    assert 'runtime_user=$(runtime_identity)' in prepare
    assert '"$ROOT/state" "$ROOT/state/parser-queue"' in prepare
    assert 'The workspace directory owner does not match the configured application user.' in prepare
    assert 'The workspace directory permissions changed. Stop and inspect the workspace.' in prepare
    assert 'install -d -m 700 "$ROOT/state" "$ROOT/state/parser-queue"' not in prepare


def test_backup_uses_storage_identity_in_a_networkless_container():
    script = (Path(__file__).parents[1] / 'manage.sh').read_text()
    backup = script.split('  backup)', 1)[1].split('  restore)', 1)[0]
    assert 'docker run --rm --network none' in backup
    assert '--cap-drop ALL' in backup
    assert '--security-opt no-new-privileges:true' in backup
    assert '--env CONTAINERIZED=1' in backup
    assert 'state_uid=$(stat -c \'%u\' "$ROOT/state")' in backup
    assert 'state_gid=$(stat -c \'%g\' "$ROOT/state")' in backup
    assert 'runtime_user=$(runtime_identity)' in backup
    assert '"$runtime_user" == "$state_uid:$state_gid"' in backup
    assert '--user "$runtime_user"' in backup
    assert 'src=$ROOT/state,dst=/state,readonly' in backup
    assert 'mktemp -d "$parent/.harbinger-backup.XXXXXXXX"' in backup
    assert 'chown -R --no-dereference "$(id -u):$(id -g)"' not in backup
    assert '"$destination" != "$ROOT/state"' in backup
    assert '"$destination" != "$ROOT/state/"*' in backup
    assert 'mv -T -n -- "$stage/$name" "$destination"' in backup
    assert 'preserve_stage_on_failure' in backup


def test_restore_uses_runtime_identity_and_atomic_staging():
    script = (Path(__file__).parents[1] / 'manage.sh').read_text()
    restore = script.split('  restore)', 1)[1].split('  help|*)', 1)[0]
    assert 'runtime_user=$(runtime_identity)' in restore
    assert '--user "$runtime_user"' in restore
    assert 'mktemp -d "$ROOT/.harbinger-restore.XXXXXXXX"' in restore
    assert 'src=$stage,dst=/restore-root' in restore
    assert 'mv -T -n -- "$stage/state" "$ROOT/state"' in restore
    assert 'run_cli verify' not in restore
    assert restore.count('docker run --rm --network none') >= 2
    assert 'mark_encrypted_path "$stage"' in restore
    assert 'unlink -- "$stage/.storage-verified.json"' in restore
    assert '?mode=ro&immutable=1' in restore


def test_parser_receipt_acknowledgement_requires_stopped_services_and_exact_checksum():
    script = (Path(__file__).parents[1] / 'manage.sh').read_text()
    receipts = script.split('  parser-receipts)', 1)[1].split('  backup)', 1)[0]
    assert receipts.count('require_services_stopped') == 2
    assert 'run_cli parser-receipts' in receipts
    assert 'run_cli parser-ack "$2" --kind "$3" --sha256 "$4"' in receipts


def test_root_enrollment_stages_a_private_app_owned_peer_card_and_removes_it():
    script = (Path(__file__).parents[1] / 'manage.sh').read_text()
    helper = script.split('stage_peer_card() {', 1)[1].split('\n}', 1)[0]
    enroll = script.split('  enroll)', 1)[1].split('  parser-receipts)', 1)[0]
    assert 'os.O_NOFOLLOW' in helper
    assert 'before.st_uid != os.geteuid()' in helper
    assert 'before.st_dev, before.st_ino, before.st_size' in helper
    assert 'os.fchown(destination_fd, int(uid), int(gid))' in helper
    assert 'os.fchmod(destination_fd, 0o600)' in helper
    assert 'mktemp "$ROOT/.harbinger-peer-card.XXXXXXXX"' in enroll
    assert 'stage_peer_card "$card" "$staged_card" "$runtime_uid" "$runtime_gid"' in enroll
    assert 'trap cleanup_staged_card EXIT' in enroll
    assert 'rm -f -- "$staged_card"' in enroll


def test_peer_card_staging_copies_only_a_stable_regular_file(tmp_path):
    source = tmp_path / 'peer-card.json'
    source.write_text('{"synthetic":true}\n')
    source.chmod(0o600)
    destination = tmp_path / 'stage'
    destination.touch(mode=0o600)
    script = (Path(__file__).parents[1] / 'manage.sh').read_text()
    helper = tmp_path / 'stage-peer-card.sh'
    helper.write_text(script.split('case "${1:-help}"', 1)[0] + '\nstage_peer_card "$@"\n')
    result = subprocess.run(
        ['bash', str(helper), str(source), str(destination), str(os.getuid()), str(os.getgid())],
        text=True, capture_output=True,
    )
    assert result.returncode == 0, result.stderr
    assert destination.read_text() == source.read_text()
    assert destination.stat().st_mode & 0o777 == 0o600
    symlink = tmp_path / 'peer-card-link.json'
    symlink.symlink_to(source)
    rejected = subprocess.run(
        ['bash', str(helper), str(symlink), str(destination), str(os.getuid()), str(os.getgid())],
        text=True, capture_output=True,
    )
    assert rejected.returncode != 0
    assert destination.read_text() == source.read_text()
