#!/usr/bin/env bash
# Test the shell completions and the source installer without a running daemon.
# Needs bash-completion, zsh, and fish. A stand-in `minsec` on PATH answers the
# data queries with canned output in the real CLI's formats.
set -euo pipefail
repo=$(cd -- "$(dirname -- "$0")/.." && pwd)
completions="$repo/completions"
temp=$(mktemp -d -t minsec-completions.XXXXXXXX)
trap 'rm -rf -- "$temp"' EXIT
fail() { echo "$*" >&2; exit 1; }

# --- Drift: every subcommand and long option in --help appears in each script.
minsec=${MINSEC:-$repo/target/debug/minsec}
minsec_sync=${MINSEC_SYNC:-$repo/target/debug/minsec-sync}
[[ -x $minsec && -x $minsec_sync ]] || cargo build -q -p minsec -p minsec-sync
check_drift() {
    local binary=$1 name=$2 sub option
    local subcommands
    subcommands=$("$binary" --help | awk '/^Commands:/ { on = 1; next } /^$/ { on = 0 } on { print $1 }')
    [[ -n $subcommands ]] || fail "no subcommands parsed from $binary --help"
    for sub in $subcommands; do
        for script in "$completions/bash/$name" "$completions/zsh/_$name" "$completions/fish/$name.fish"; do
            grep -qw -- "$sub" "$script" || fail "$script lacks subcommand $sub"
        done
        [[ $sub == help ]] && continue
        for option in $("$binary" "$sub" --help | grep -oE -- '(^| )--[a-z-]+' | tr -d ' ' | sort -u); do
            for script in "$completions/bash/$name" "$completions/zsh/_$name"; do
                grep -q -- "$option" "$script" || fail "$script lacks $sub option $option"
            done
            grep -q -- "-l ${option#--}" "$completions/fish/$name.fish" ||
                fail "$completions/fish/$name.fish lacks $sub option $option"
        done
    done
}
check_drift "$minsec" minsec
check_drift "$minsec_sync" minsec-sync

# --- Installer.
export XDG_DATA_HOME="$temp/user data" XDG_CONFIG_HOME="$temp/user config"
unset BASH_COMPLETION_DIR ZSH_COMPLETION_DIR FISH_COMPLETION_DIR BASH_COMPLETION_USER_DIR DESTDIR PREFIX
"$repo/scripts/install-completions.sh" --user
for command in minsec minsec-sync; do
    cmp "$completions/bash/$command" "$XDG_DATA_HOME/bash-completion/completions/$command"
    cmp "$completions/zsh/_$command" "$XDG_DATA_HOME/zsh/site-functions/_$command"
    cmp "$completions/fish/$command.fish" "$XDG_CONFIG_HOME/fish/completions/$command.fish"
done
for layout in vendor-completions site-functions; do
    DESTDIR="$temp/$layout" PREFIX=/usr ZSH_COMPLETION_DIR="/usr/share/zsh/$layout" \
        "$repo/scripts/install-completions.sh" --system
    for command in minsec minsec-sync; do
        for relative in "bash-completion/completions/$command" "zsh/$layout/_$command" "fish/vendor_completions.d/$command.fish"; do
            test "$(stat -c %a "$temp/$layout/usr/share/$relative")" = 644
        done
    done
done
DESTDIR="$temp/only-bash" "$repo/scripts/install-completions.sh" --system --shell bash
test -f "$temp/only-bash/usr/local/share/bash-completion/completions/minsec"
test ! -e "$temp/only-bash/usr/local/share/zsh"
if "$repo/scripts/install-completions.sh" --shell unknown; then
    fail "installer accepted an unknown shell"
fi

# --- Stand-ins for the binaries: fish only autoloads completions for commands
# on PATH, and the data queries must not depend on a daemon or the host.
mkdir -p "$temp/bin"
cat > "$temp/bin/minsec" <<'STUB'
#!/usr/bin/env bash
config_dir=/etc/minsec
while [[ ${1-} == -* ]]; do
    case $1 in
        --config-dir) config_dir=$2; shift 2 ;;
        --config-dir=*) config_dir=${1#*=}; shift ;;
        *) shift ;;
    esac
done
case ${1-} in
    filters)
        printf '%s %-16s %s\n' '*' sshd 'OpenSSH authentication failures' \
            ' ' nginx-auth 'nginx basic auth failures' ' ' postfix 'Postfix SASL failures'
        [[ $config_dir == /etc/minsec ]] || printf '%s %-16s %s\n' ' ' "custom-$(basename "$config_dir")" 'Custom filter'
        ;;
    list) printf '%-44s %-12s %s\n' 203.0.113.7 59m sshd 2001:db8::/32 - manual ;;
    *) exit 1 ;;
esac
STUB
chmod +x "$temp/bin/minsec"
ln -s /bin/false "$temp/bin/minsec-sync"
export PATH="$temp/bin:$PATH"

# expect SHELL LINE WORD... [-- UNWANTED...]: the completions for LINE must
# include every WORD and none of the UNWANTED ones.
expect() {
    local shell=$1 line=$2 word got
    shift 2
    got=$("complete_$shell" "$line" | sort -u)
    local -a wanted=() unwanted=()
    for word; do
        if [[ $word == -- ]]; then
            unwanted=("${@:2}")
            break
        fi
        wanted+=("$word")
        shift
    done
    for word in "${wanted[@]}"; do
        grep -qxF -- "$word" <<< "$got" || fail "$shell: $word missing for '$line': $(tr '\n' ' ' <<< "$got")"
    done
    for word in "${unwanted[@]}"; do
        ! grep -qxF -- "$word" <<< "$got" || fail "$shell: $word offered for '$line': $(tr '\n' ' ' <<< "$got")"
    done
}
# The cases are the same for every shell; SHELL is bash, zsh, or fish.
expect_all() {
    local shell=$1
    expect "$shell" 'minsec ' check unban help
    expect "$shell" 'minsec che' check -- daemon
    expect "$shell" 'minsec -' --config-dir --json --version
    expect "$shell" 'minsec check --' --all --config-dir -- --replay
    expect "$shell" 'minsec ban 1.2.3.4 --' --ttl -- --all
    expect "$shell" 'minsec daemon --backend ' nft null exec
    expect "$shell" 'minsec enable ' nginx-auth postfix -- sshd
    expect "$shell" 'minsec disable ' sshd -- nginx-auth
    expect "$shell" 'minsec test ' sshd nginx-auth postfix
    expect "$shell" 'minsec unban ' 203.0.113.7 2001:db8::/32
    expect "$shell" 'minsec -c /tmp/x enable ' custom-x nginx-auth
    expect "$shell" 'minsec enable -c /tmp/z ' custom-z
    expect "$shell" 'minsec enable sshd ' -- nginx-auth postfix
    expect "$shell" 'minsec help ' check unban
    expect "$shell" 'minsec-sync ' enroll pull status
    expect "$shell" 'minsec-sync pu' pull -- report
    expect "$shell" 'minsec-sync pull --' --dry-run --config
    expect "$shell" 'minsec-sync help ' pull
}

# --- Bash, through bash-completion's lazy loader from the installed user dir.
for command in minsec minsec-sync; do
    bash -n "$completions/bash/$command"
done
complete_bash() {
    BASH_COMPLETION_USER_DIR="$temp/bash-completion" bash -c '
        set +u
        source /usr/share/bash-completion/bash_completion
        COMP_LINE=$1
        COMP_POINT=${#COMP_LINE}
        read -ra COMP_WORDS <<< "$COMP_LINE"
        [[ $COMP_LINE == *" " ]] && COMP_WORDS+=("")
        COMP_CWORD=$((${#COMP_WORDS[@]} - 1))
        _completion_loader "${COMP_WORDS[0]}" || [[ $? == 124 ]]
        COMPREPLY=()
        "$(complete -p "${COMP_WORDS[0]}" | sed "s/.*-F \([^ ]*\).*/\1/")" \
            "${COMP_WORDS[0]}" "${COMP_WORDS[COMP_CWORD]}" "${COMP_WORDS[COMP_CWORD - 1]}"
        printf "%s\n" "${COMPREPLY[@]}"' bash "$1"
}
# bash-completion 2.11 splits user directories on spaces, so the lazy loader
# uses a space-free directory; the installer checks above cover such paths.
BASH_COMPLETION_DIR="$temp/bash-completion/completions" \
    "$repo/scripts/install-completions.sh" --user --shell bash >/dev/null
expect_all bash
expect bash 'minsec test sshd /et' /etc
# Bash splits words at colons; the script trims the prefix readline keeps.
expect bash 'minsec unban 2001:' db8::/32

# --- Zsh, driven through zle in a pty so _arguments runs for real.
for command in minsec minsec-sync; do
    zsh -n "$completions/zsh/_$command"
done
complete_zsh() {
    zsh -f -s "$XDG_DATA_HOME/zsh/site-functions" "$1" <<'ZSH'
zmodload zsh/zpty
out=$(mktemp)
zpty z zsh -f -i
zpty -w z "PS1='%% '; fpath=(${(q)1} \$fpath); autoload -Uz compinit; compinit -D -i"
zpty -w z "zstyle ':completion:*' menu no; bindkey '^I' complete-word"
# Record every candidate the completion system would add.
zpty -w z "compadd() { local -a m; builtin compadd -O m \"\$@\"; print -rl -- \$m >> ${(q)out}; builtin compadd \"\$@\" }"
zpty -w z "print -- SET""UP"
zpty -r -m z log '*SETUP*' || exit 1
zpty -n -w z "$2"$'\t'
zpty -w z $'\C-u'"print -- DO""NE"
zpty -r -m z log '*DONE*' || exit 1
zpty -d z
grep -v '^$' -- $out || true
rm -f -- $out
ZSH
}
expect_all zsh
expect zsh 'minsec test sshd /et' etc # _files reports the last path component
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

# --- Fish autoloads the installed files for commands on PATH.
for command in minsec minsec-sync; do
    fish -n "$completions/fish/$command.fish"
done
complete_fish() {
    # string replace fails when no line had a description to strip.
    # shellcheck disable=SC2016 # $argv is fish's.
    fish -c 'complete -C "$argv[1]" | string replace -r "\t.*" ""; true' "$1"
}
expect_all fish
expect fish 'minsec test sshd /et' /etc/

echo "Completion and installer checks passed."
