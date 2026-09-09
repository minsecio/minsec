#!/usr/bin/env bash
# Install previously generated completions; never run Cargo as root.
set -euo pipefail

usage() {
    echo "usage: $0 [--user|--system] [--shell bash|zsh|fish|all] [--from DIRECTORY]"
    echo "Defaults: --user --shell all --from REPO/target/completions"
    echo "System installs: PREFIX=/usr/local, DESTDIR=; override shell directories with"
    echo "BASH_COMPLETION_DIR, ZSH_COMPLETION_DIR, or FISH_COMPLETION_DIR."
}
die() { echo "$*" >&2; exit 2; }
repo=$(cd -- "$(dirname -- "$0")/.." && pwd)
source_dir="$repo/target/completions"
mode=user
shell=all
while (( $# )); do
    case "$1" in
        --user) mode=user; shift ;;
        --system) mode=system; shift ;;
        --shell|--from)
            (( $# >= 2 )) || die "missing value for $1"
            if [[ $1 == --shell ]]; then shell=$2; else source_dir=$2; fi
            shift 2 ;;
        -h|--help) usage; exit 0 ;;
        *) usage >&2; die "unknown argument: $1" ;;
    esac
done
case "$shell" in bash|zsh|fish|all) ;; *) die "unknown shell: $shell" ;; esac
stage=${DESTDIR:-}
[[ -z $stage || $stage == /* ]] || die "DESTDIR must be absolute"
if [[ $mode == user ]]; then
    [[ -z $stage ]] || die "DESTDIR requires --system"
    data_dir=${XDG_DATA_HOME:-"$HOME/.local/share"}
    config_dir=${XDG_CONFIG_HOME:-"$HOME/.config"}
    bash_dir=${BASH_COMPLETION_DIR:-"$data_dir/bash-completion/completions"}
    zsh_dir=${ZSH_COMPLETION_DIR:-"$data_dir/zsh/site-functions"}
    fish_dir=${FISH_COMPLETION_DIR:-"$config_dir/fish/completions"}
else
    prefix=${PREFIX:-/usr/local}
    [[ $prefix == /* ]] || die "PREFIX must be absolute"
    bash_dir=${BASH_COMPLETION_DIR:-"$prefix/share/bash-completion/completions"}
    zsh_dir="$prefix/share/zsh/site-functions"
    if [[ $prefix == /usr && -f /etc/debian_version ]]; then
        zsh_dir="$prefix/share/zsh/vendor-completions"
    fi
    zsh_dir=${ZSH_COMPLETION_DIR:-$zsh_dir}
    fish_dir=${FISH_COMPLETION_DIR:-"$prefix/share/fish/vendor_completions.d"}
fi

shells=("$shell")
[[ $shell != all ]] || shells=(bash zsh fish)
# Check every input before installing anything.
for selected in "${shells[@]}"; do
    for command in minsec minsec-sync; do
        case "$selected" in
            bash) filename="$command.bash"; directory=$bash_dir ;;
            zsh) filename="_$command"; directory=$zsh_dir ;;
            fish) filename="$command.fish"; directory=$fish_dir ;;
        esac
        [[ $directory == /* ]] || die "completion directories must be absolute: $directory"
        [[ -s "$source_dir/$selected/$filename" ]] ||
            die "missing $source_dir/$selected/$filename; run scripts/generate-completions.sh first"
    done
done
for selected in "${shells[@]}"; do
    case "$selected" in
        bash) directory=$bash_dir; files=(minsec.bash minsec-sync.bash) ;;
        zsh) directory=$zsh_dir; files=(_minsec _minsec-sync) ;;
        fish) directory=$fish_dir; files=(minsec.fish minsec-sync.fish) ;;
    esac
    install -d -m 0755 -- "$stage$directory"
    for filename in "${files[@]}"; do
        install -m 0644 -- "$source_dir/$selected/$filename" "$stage$directory/$filename"
    done
    echo "Installed $selected completions to $stage$directory"
done
if [[ -z $stage ]]; then
    if [[ $shell == all || $shell == bash ]]; then
        echo "Bash: enable bash-completion, then start a new shell."
        echo "For this shell (also works with older loaders and paths containing spaces):"
        printf '  source %q\n  source %q\n' "$bash_dir/minsec.bash" "$bash_dir/minsec-sync.bash"
    fi
    if [[ $shell == all || $shell == zsh ]]; then
        printf 'Zsh: ensure %q is on fpath before running compinit.\n' "$zsh_dir"
        # shellcheck disable=SC2016 # Print literal Zsh code for the user.
        printf '  fpath=(%q $fpath)\n  autoload -Uz compinit; compinit\n' "$zsh_dir"
    fi
    if [[ $shell == all || $shell == fish ]]; then
        echo "Fish: start a new shell; the completion directory must be on fish_complete_path."
    fi
fi
