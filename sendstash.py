#!/usr/bin/env python3
import os
import sys
import yaml
import subprocess
import argparse
import tempfile
import re
from datetime import datetime, timedelta


class SendStash:
    def __init__(self, config_path=None):
        self.config_path = self._find_config_file(config_path)
        if not self.config_path:
            print("Error: Could not find config.yaml.")
            print("Please place it in one of the documented locations")
            sys.exit(1)

        print(f"Loading config from: {self.config_path}")
        self.config = self._load_config(self.config_path)
        self.project_path = None

    def _find_config_file(self, specified_path):
        """Finds the config file in a prioritized list of locations."""
        if specified_path and os.path.exists(specified_path):
            return specified_path

        # Path specified by environment variable
        env_path = os.getenv('SENDSTASH_CONFIG_PATH')
        if env_path and os.path.exists(env_path):
            return env_path

        # User-specific config directory
        user_config_path = os.path.expanduser("~/.config/sendstash/config.yaml")
        if os.path.exists(user_config_path):
            return user_config_path

        # In an adjacent directory: ../sendstash-config/config.yaml
        script_dir = os.path.dirname(os.path.realpath(__file__))
        adjacent_config_path = os.path.join(script_dir, '..', 'sendstash-config', 'config.yaml')
        if os.path.exists(adjacent_config_path):
            return os.path.normpath(adjacent_config_path)

        # In the same directory as the script
        script_config_path = os.path.join(script_dir, 'config.yaml')
        if os.path.exists(script_config_path):
            return script_config_path

        return None

    def _load_config(self, config_path):
        """Loads the configuration from a YAML file."""
        with open(config_path, 'r') as f:
            config = yaml.safe_load(f)

        # Resolve password from password_cmd if needed
        smb = config.get('smb', {})
        if 'password_cmd' in smb and 'password' not in smb:
            try:
                result = subprocess.run(
                    smb['password_cmd'], shell=True,
                    capture_output=True, text=True, check=True
                )
                smb['password'] = result.stdout.strip()
            except subprocess.CalledProcessError as e:
                print(f"Error running password_cmd: {e}")
                sys.exit(1)

        # Expand project paths
        root = os.path.expanduser(config.get('root', ''))
        if 'projects' in config:
            for name, project in config['projects'].items():
                project['path'] = os.path.expanduser(project['path'].format(root=root))

        return config

    def get_project_choices(self):
        """Returns a list of project names from the config."""
        return list(self.config.get('projects', {}).keys())

    def set_project(self, project_name):
        """Set the working directory to a configured project's path."""
        projects = self.config.get('projects', {})
        if project_name not in projects:
            print(f"Error: Project '{project_name}' not found in config.")
            print(f"Available projects: {', '.join(projects.keys())}")
            sys.exit(1)
        self.project_path = projects[project_name]['path']
        if not os.path.isdir(self.project_path):
            print(f"Error: Project path does not exist: {self.project_path}")
            sys.exit(1)
        print(f"Using project: {project_name} ({self.project_path})")

    def _run_command(self, command, cwd=None, interactive=False, capture=False):
        """Runs a command and streams its output."""
        if capture:
            result = subprocess.run(
                command, cwd=cwd, shell=isinstance(command, str),
                capture_output=True, text=True
            )
            return result
        elif interactive:
            process = subprocess.Popen(command, cwd=cwd, shell=isinstance(command, str))
            process.wait()
            return process.returncode
        else:
            process = subprocess.Popen(
                command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                universal_newlines=True, cwd=cwd, shell=isinstance(command, str)
            )
            for line in process.stdout:
                print(line, end='')
            process.wait()
            return process.returncode

    def sync_config(self):
        """Syncs the configuration file itself based on 'config_sync' settings."""
        if 'config_sync' not in self.config:
            print("Warning: --sync-config was passed, but 'config_sync' section is not defined in config.yaml.")
            return

        sync_settings = self.config['config_sync']
        command = sync_settings.get('command')

        if not command:
            print("Error: 'config_sync' section is missing the 'command' key.")
            return

        config_dir = os.path.dirname(self.config_path)

        print(f"Syncing configuration using command: '{command}' in '{config_dir}'")
        return_code = self._run_command(command, cwd=config_dir)

        if return_code == 0:
            print("Configuration sync completed successfully.")
            print("Reloading configuration...")
            self.config = self._load_config(self.config_path)
        else:
            print(f"Configuration sync failed with return code: {return_code}")
            sys.exit(1)

    def _get_cwd(self):
        """Get the working directory — project path if set, otherwise current dir."""
        return self.project_path or None

    def _get_repo_name(self):
        """Derive repo name from current git repo's root directory name."""
        result = self._run_command('git rev-parse --show-toplevel', cwd=self._get_cwd(), capture=True)
        if result.returncode != 0:
            print("Error: Not inside a git repository.")
            sys.exit(1)
        return os.path.basename(result.stdout.strip())

    def _get_branch_name(self):
        """Get the current branch name."""
        result = self._run_command('git rev-parse --abbrev-ref HEAD', cwd=self._get_cwd(), capture=True)
        if result.returncode != 0:
            print("Error: Could not determine current branch.")
            sys.exit(1)
        return result.stdout.strip()

    def _sanitize_name(self, name):
        """Sanitize a name for use in filenames (replace / with _)."""
        return re.sub(r'[/\\]', '_', name)

    def _sanitize_for_filename(self, text, max_len=40):
        """Sanitize arbitrary text for use in a filename component."""
        # Replace whitespace and unsafe chars with hyphens, collapse runs, strip edges
        sanitized = re.sub(r'[^\w.-]+', '-', text).strip('-')
        return sanitized[:max_len].rstrip('-')

    def _smb_cmd(self, subcmd):
        """Build and run an smbclient command with auth from config."""
        smb = self.config['smb']
        server = smb['server']
        username = smb['username']
        password = smb['password']

        cmd = ['smbclient', server, '-U', f'{username}%{password}', '-c', subcmd]
        return subprocess.run(cmd, capture_output=True, text=True)

    def _get_remote_dir(self):
        """Get the base remote directory from config."""
        return self.config['smb'].get('remote_dir', 'stash-sync')

    def _get_stash_message(self, stash_ref):
        """Get the message for a stash ref from git stash list."""
        result = self._run_command('git stash list', cwd=self._get_cwd(), capture=True)
        if result.returncode != 0 or not result.stdout.strip():
            return ''
        # stash_ref is like "stash@{0}", look for matching line
        for line in result.stdout.strip().split('\n'):
            if line.startswith(stash_ref):
                # Format: "stash@{0}: On branch: message"
                parts = line.split(':', 2)
                if len(parts) >= 3:
                    return parts[2].strip()
                return ''
        return ''

    def push(self, message=None, stash_ref='stash@{0}'):
        """Push a stash patch to the SMB share."""
        repo_name = self._get_repo_name()
        branch = self._get_branch_name()
        remote_dir = self._get_remote_dir()

        # Generate the patch from stash
        result = self._run_command(f'git stash show -p "{stash_ref}"', cwd=self._get_cwd(), capture=True)
        if result.returncode != 0:
            print(f"Error: Could not generate patch from {stash_ref}")
            print(result.stderr)
            sys.exit(1)

        patch_content = result.stdout
        if not patch_content.strip():
            print(f"Error: Empty patch from {stash_ref}")
            sys.exit(1)

        # Get stash name from git for the filename
        stash_name = self._get_stash_message(stash_ref)

        # Resolve .msg content: explicit flag > git stash name > empty
        if message is None:
            message = stash_name

        # Generate filename
        timestamp = datetime.now().strftime('%Y-%m-%d_%H-%M-%S')
        sanitized_branch = self._sanitize_name(branch)
        # Include stash name in filename if available: branch_stashname_timestamp
        stash_label = self._sanitize_for_filename(stash_name) if stash_name else ''
        if stash_label:
            base_name = f"{sanitized_branch}_{stash_label}_{timestamp}"
        else:
            base_name = f"{sanitized_branch}_{timestamp}"
        filename = f"{base_name}.patch"
        msg_filename = f"{base_name}.msg"

        # Write patch to temp file
        with tempfile.NamedTemporaryFile(mode='w', suffix='.patch', delete=False) as f:
            f.write(patch_content)
            temp_patch_path = f.name

        # Write message to temp file
        with tempfile.NamedTemporaryFile(mode='w', suffix='.msg', delete=False) as f:
            f.write(message)
            temp_msg_path = f.name

        try:
            # Upload to SMB share
            # mkdir the remote_dir and repo subdir (ignore "already exists" errors)
            # then upload the patch and message
            smb_subcmd = (
                f"mkdir {remote_dir}; "
                f"mkdir {remote_dir}\\{repo_name}; "
                f"cd {remote_dir}\\{repo_name}; "
                f"put {temp_patch_path} {filename}; "
                f"put {temp_msg_path} {msg_filename}"
            )
            result = self._smb_cmd(smb_subcmd)

            # Filter out "already exists" errors — those are expected from mkdir
            stderr_lines = result.stderr.strip().split('\n') if result.stderr else []
            real_errors = [
                line for line in stderr_lines
                if line.strip() and 'NT_STATUS_OBJECT_NAME_COLLISION' not in line
            ]

            if result.returncode != 0 and real_errors:
                print("Error uploading patch to SMB share:")
                print('\n'.join(real_errors))
                sys.exit(1)

            print(f"Pushed stash patch to: {remote_dir}/{repo_name}/{filename}")
            if message:
                print(f"Message: {message}")
        finally:
            os.unlink(temp_patch_path)
            os.unlink(temp_msg_path)

    def _fetch_messages(self, repo_name, patches):
        """Batch-download .msg files for a list of patches. Returns dict of patch_name -> message."""
        remote_dir = self._get_remote_dir()
        messages = {}

        with tempfile.TemporaryDirectory() as tmpdir:
            smb_subcmd = (
                f"cd {remote_dir}\\{repo_name}; "
                f"prompt OFF; "
                f"lcd {tmpdir}; "
                f"mget *.msg"
            )
            self._smb_cmd(smb_subcmd)

            # Read downloaded .msg files and match to patches by base name
            for name, _, _ in patches:
                base = name.rsplit('.patch', 1)[0]
                msg_path = os.path.join(tmpdir, f"{base}.msg")
                if os.path.exists(msg_path):
                    with open(msg_path, 'r') as f:
                        messages[name] = f.read().strip()

        return messages

    def list_patches(self):
        """List available patches on the SMB share for the current repo."""
        repo_name = self._get_repo_name()
        remote_dir = self._get_remote_dir()

        smb_subcmd = f"ls {remote_dir}\\{repo_name}\\*.patch"
        result = self._smb_cmd(smb_subcmd)

        if result.returncode != 0:
            if 'NO_SUCH_FILE' in (result.stderr or '') or 'NT_STATUS_OBJECT_NAME_NOT_FOUND' in (result.stderr or ''):
                print(f"No patches found for repo '{repo_name}'.")
                return []
            print("Error listing patches:")
            print(result.stderr)
            return []

        # Parse smbclient ls output
        patches = self._parse_ls_output(result.stdout)

        if not patches:
            print(f"No patches found for repo '{repo_name}'.")
            return []

        # Fetch messages for all patches in one smbclient call
        messages = self._fetch_messages(repo_name, patches)

        print(f"Patches for '{repo_name}':")
        for i, (name, size, date) in enumerate(patches, 1):
            msg = messages.get(name, '')
            msg_display = f'  "{msg}"' if msg else ''
            print(f"  {i}. {name}  ({size} bytes, {date}){msg_display}")

        return patches

    def _parse_ls_output(self, output):
        """Parse smbclient ls output into list of (filename, size, date_string)."""
        patches = []
        for line in output.strip().split('\n'):
            line = line.strip()
            if not line or not line.endswith('.patch'):
                # Try to parse lines that contain .patch
                pass

            # smbclient ls format: "  filename    A    size  date"
            # Match lines containing .patch files
            match = re.match(
                r'\s*(\S+\.patch)\s+[A-Za-z]*\s+(\d+)\s+(.*)',
                line
            )
            if match:
                name = match.group(1)
                size = match.group(2)
                date = match.group(3).strip()
                patches.append((name, size, date))

        # Sort by filename (which contains timestamp) so newest is last
        patches.sort(key=lambda x: x[0])
        return patches

    def pull(self, latest=True, pick=False):
        """Pull a stash patch from the SMB share and apply it."""
        repo_name = self._get_repo_name()
        remote_dir = self._get_remote_dir()

        # List available patches
        smb_subcmd = f"ls {remote_dir}\\{repo_name}\\*.patch"
        result = self._smb_cmd(smb_subcmd)

        if result.returncode != 0:
            print(f"No patches found for repo '{repo_name}'.")
            return

        patches = self._parse_ls_output(result.stdout)
        if not patches:
            print(f"No patches found for repo '{repo_name}'.")
            return

        if pick:
            # Fetch messages for display
            messages = self._fetch_messages(repo_name, patches)

            # Show list and let user choose
            print(f"Available patches for '{repo_name}':")
            for i, (name, size, date) in enumerate(patches, 1):
                msg = messages.get(name, '')
                msg_display = f'  "{msg}"' if msg else ''
                print(f"  {i}. {name}  ({size} bytes, {date}){msg_display}")

            try:
                choice = int(input("\nSelect patch number: "))
                if choice < 1 or choice > len(patches):
                    print("Invalid selection.")
                    return
                selected = patches[choice - 1]
            except (ValueError, EOFError):
                print("Invalid selection.")
                return
        else:
            # Default: latest (last in sorted list)
            selected = patches[-1]

        patch_name = selected[0]
        print(f"Downloading: {patch_name}")

        # Download patch to temp file
        with tempfile.NamedTemporaryFile(mode='w', suffix='.patch', delete=False) as f:
            temp_path = f.name

        try:
            smb_subcmd = (
                f"cd {remote_dir}\\{repo_name}; "
                f"get {patch_name} {temp_path}"
            )
            result = self._smb_cmd(smb_subcmd)

            if result.returncode != 0:
                print("Error downloading patch:")
                print(result.stderr)
                return

            # Apply the patch
            apply_result = self._run_command(f'git apply {temp_path}', cwd=self._get_cwd(), capture=True)
            if apply_result.returncode != 0:
                print("Error applying patch:")
                print(apply_result.stderr)
                print("\nPatch saved at:", temp_path)
                return

            print(f"Successfully applied patch: {patch_name}")
        finally:
            if os.path.exists(temp_path):
                os.unlink(temp_path)

    def clean(self, all_patches=False, older_than=None):
        """Remove old patches from the SMB share for the current repo."""
        repo_name = self._get_repo_name()
        remote_dir = self._get_remote_dir()

        # List existing patches
        smb_subcmd = f"ls {remote_dir}\\{repo_name}\\*.patch"
        result = self._smb_cmd(smb_subcmd)

        if result.returncode != 0:
            print(f"No patches found for repo '{repo_name}'.")
            return

        patches = self._parse_ls_output(result.stdout)
        if not patches:
            print(f"No patches found for repo '{repo_name}'.")
            return

        to_delete = []

        if all_patches:
            to_delete = [p[0] for p in patches]
        elif older_than is not None:
            cutoff = datetime.now() - timedelta(days=older_than)
            for name, size, date in patches:
                # Extract timestamp from filename: branch_YYYY-MM-DD_HH-MM-SS.patch
                ts_match = re.search(r'(\d{4}-\d{2}-\d{2}_\d{2}-\d{2}-\d{2})\.patch$', name)
                if ts_match:
                    try:
                        patch_time = datetime.strptime(ts_match.group(1), '%Y-%m-%d_%H-%M-%S')
                        if patch_time < cutoff:
                            to_delete.append(name)
                    except ValueError:
                        continue

        if not to_delete:
            print("No patches to clean.")
            return

        # Build delete commands for both .patch and .msg files
        delete_cmds = []
        for name in to_delete:
            delete_cmds.append(f"del {name}")
            msg_name = name.rsplit('.patch', 1)[0] + '.msg'
            delete_cmds.append(f"del {msg_name}")

        smb_subcmd = f"cd {remote_dir}\\{repo_name}; {'; '.join(delete_cmds)}"
        result = self._smb_cmd(smb_subcmd)

        # Filter out "not found" errors for .msg files that may not exist
        stderr_lines = result.stderr.strip().split('\n') if result.stderr else []
        real_errors = [
            line for line in stderr_lines
            if line.strip()
            and 'NT_STATUS_OBJECT_NAME_NOT_FOUND' not in line
            and 'NT_STATUS_NO_SUCH_FILE' not in line
        ]

        if result.returncode != 0 and real_errors:
            print("Error cleaning patches:")
            print('\n'.join(real_errors))
            return

        print(f"Cleaned {len(to_delete)} patch(es) from '{repo_name}':")
        for name in to_delete:
            print(f"  - {name}")


def main():
    # Pre-parse --config so we can load projects before building the full parser
    pre_parser = argparse.ArgumentParser(add_help=False)
    pre_parser.add_argument('--config')
    pre_parser.add_argument('--sync-config', action='store_true')
    pre_args, _ = pre_parser.parse_known_args()

    stash = SendStash(config_path=pre_args.config)

    if pre_args.sync_config:
        stash.sync_config()

    project_choices = stash.get_project_choices() or None

    parser = argparse.ArgumentParser(
        description="Sync git stash patches via SMB share."
    )
    parser.add_argument('--config', help="Path to config.yaml")
    parser.add_argument('--sync-config', action='store_true', help="Sync the configuration from its source before running the command")

    subparsers = parser.add_subparsers(dest='command', help="Available commands")

    # Shared parent parser for --project
    project_parser = argparse.ArgumentParser(add_help=False)
    project_parser.add_argument(
        '--project', '-p', choices=project_choices,
        help="Use a configured project instead of the current directory"
    )

    # push
    push_parser = subparsers.add_parser('push', parents=[project_parser], help="Push a stash patch to the SMB share")
    push_parser.add_argument('--message', '-m', help="Optional message/description for the patch")
    push_parser.add_argument('--stash', default='stash@{0}', help="Stash reference (default: stash@{0})")

    # pull
    pull_parser = subparsers.add_parser('pull', parents=[project_parser], help="Pull and apply a stash patch from the SMB share")
    pull_group = pull_parser.add_mutually_exclusive_group()
    pull_group.add_argument('--latest', action='store_true', default=True, help="Pull the most recent patch (default)")
    pull_group.add_argument('--pick', action='store_true', help="Interactively choose which patch to apply")

    # list
    subparsers.add_parser('list', parents=[project_parser], help="List available patches on the SMB share")

    # clean
    clean_parser = subparsers.add_parser('clean', parents=[project_parser], help="Remove old patches from the SMB share")
    clean_group = clean_parser.add_mutually_exclusive_group(required=True)
    clean_group.add_argument('--all', action='store_true', help="Remove all patches for the current repo")
    clean_group.add_argument('--older-than', type=int, metavar='DAYS', help="Remove patches older than N days")

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        return

    if args.project:
        stash.set_project(args.project)

    if args.command == 'push':
        stash.push(message=args.message, stash_ref=args.stash)
    elif args.command == 'pull':
        stash.pull(latest=not args.pick, pick=args.pick)
    elif args.command == 'list':
        stash.list_patches()
    elif args.command == 'clean':
        stash.clean(all_patches=args.all, older_than=args.older_than)


if __name__ == '__main__':
    main()
