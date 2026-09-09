#!/usr/bin/env bash
# Test generated completions and the source installer without a running daemon.
set -euo pipefail
repo=$(cd -- "$(dirname -- "$0")/.." && pwd)
generated="$repo/target/completions"
temp=$(mktemp -d -t minsec-completions.XXXXXXXX)
trap 'rm -rf -- "$temp"' EXIT
export XDG_DATA_HOME="$temp/user data" XDG_CONFIG_HOME="$temp/user config"
unset BASH_COMPLETION_DIR ZSH_COMPLETION_DIR FISH_COMPLETION_DIR BASH_COMPLETION_USER_DIR DESTDIR PREFIX
"$repo/scripts/install-completions.sh" --user
for command in minsec minsec-sync; do
    cmp "$generated/bash/$command.bash" "$XDG_DATA_HOME/bash-completion/completions/$command.bash"
    cmp "$generated/zsh/_$command" "$XDG_DATA_HOME/zsh/site-functions/_$command"
    cmp "$generated/fish/$command.fish" "$XDG_CONFIG_HOME/fish/completions/$command.fish"
done

for layout in vendor-completions site-functions; do
    DESTDIR="$temp/$layout" PREFIX=/usr ZSH_COMPLETION_DIR="/usr/share/zsh/$layout" \
        "$repo/scripts/install-completions.sh" --system
    for command in minsec minsec-sync; do
        for relative in "bash-completion/completions/$command.bash" "zsh/$layout/_$command" "fish/vendor_completions.d/$command.fish"; do
            test "$(stat -c %a "$temp/$layout/usr/share/$relative")" = 644
        done
    done
done
DESTDIR="$temp/only-bash" "$repo/scripts/install-completions.sh" --system --shell bash
test -f "$temp/only-bash/usr/local/share/bash-completion/completions/minsec.bash"
test ! -e "$temp/only-bash/usr/local/share/zsh"
if DESTDIR="$temp/missing" "$repo/scripts/install-completions.sh" --system --from "$temp/absent"; then
    echo "installer accepted missing completion files" >&2; exit 1
fi
test ! -e "$temp/missing"
if "$repo/scripts/install-completions.sh" --shell unknown; then
    echo "installer accepted an unknown shell" >&2; exit 1
fi

# Exercise Bash's lazy loader with the installed .bash filenames.
# bash-completion 2.11 splits user directories on spaces; the installer checks
# above still cover such paths, while lazy loading uses a space-free directory.
export BASH_COMPLETION_USER_DIR="$temp/bash-completion"
BASH_COMPLETION_DIR="$BASH_COMPLETION_USER_DIR/completions" \
    "$repo/scripts/install-completions.sh" --user --shell bash
if [[ -f /usr/share/bash-completion/bash_completion ]]; then
    # bash-completion and the generated scripts expect ordinary shell options.
    set +u
    # shellcheck disable=SC1091
    source /usr/share/bash-completion/bash_completion
    _completion_loader minsec || [[ $? == 124 ]]
    _completion_loader minsec-sync || [[ $? == 124 ]]
else
    # shellcheck disable=SC1091
    source "$XDG_DATA_HOME/bash-completion/completions/minsec.bash"
    # shellcheck disable=SC1091
    source "$XDG_DATA_HOME/bash-completion/completions/minsec-sync.bash"
fi
expect_bash() {
    local expected=$1 function=$2
    shift 2
    COMP_WORDS=("$@")
    COMP_CWORD=$((${#COMP_WORDS[@]} - 1))
    "$function" "${COMP_WORDS[0]}" "${COMP_WORDS[COMP_CWORD]}" "${COMP_WORDS[COMP_CWORD-1]}"
    [[ " ${COMPREPLY[*]} " == *" $expected "* ]] || {
        echo "missing Bash completion $expected for $*: ${COMPREPLY[*]}" >&2; exit 1;
    }
}
expect_bash check _minsec minsec che
expect_bash --all _minsec minsec check --a
expect_bash --ttl _minsec minsec ban --t
expect_bash --json _minsec minsec status --j
expect_bash pull _minsec-sync minsec-sync pu
expect_bash --dry-run _minsec-sync minsec-sync pull --d

for command in minsec minsec-sync; do
    bash -n "$generated/bash/$command.bash"
    zsh -n "$generated/zsh/_$command"
    fish -n "$generated/fish/$command.fish"
done
# Zsh must discover both #compdef headers even if the runner has an insecure
# fpath entry. Ignore such entries without prompting in this noninteractive test.
mkdir -m 0777 "$temp/insecure-zsh"
# shellcheck disable=SC2016
zsh -f -c '
    fpath=("$XDG_DATA_HOME/zsh/site-functions" "$1" $fpath)
    autoload -Uz compinit
    compinit -i -D || exit 1
    [[ ${fpath[(Ie)$1]} == 0 ]] || exit 1
    [[ $_comps[minsec] == _minsec && $_comps[minsec-sync] == _minsec-sync ]]
' zsh "$temp/insecure-zsh"
# Fish loads the installed files automatically and suggests subcommands/options.
# Fish requires commands on PATH before autoloading. Inert stand-ins keep this
# check independent of the binaries' architecture and any daemon configuration.
mkdir -p "$temp/bin"
ln -s /bin/false "$temp/bin/minsec"
ln -s /bin/false "$temp/bin/minsec-sync"
export PATH="$temp/bin:$PATH"
# shellcheck disable=SC2016
fish -c '
    complete -C "minsec che" | string match -qr "^check\t"; or exit 1
    complete -C "minsec ban --t" | string match -qr "^--ttl\t"; or exit 1
    complete -C "minsec-sync pu" | string match -qr "^pull\t"; or exit 1
    complete -C "minsec-sync pull --d" | string match -qr "^--dry-run\t"; or exit 1
'
echo "Completion and installer checks passed."
