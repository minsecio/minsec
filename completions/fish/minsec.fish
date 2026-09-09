# Fish completion for minsec.
#
# Subcommands and options are static; filter names come from `minsec filters`
# and active bans from `minsec list` at completion time. Data queries fail
# silently, e.g. when the daemon is not running or the socket is not readable.

# Print the subcommand on the command line, if any.
function __minsec_subcommand
    set -l tokens (commandline -opc)
    set -e tokens[1]
    argparse -s c/config-dir= json h/help V/version -- $tokens 2>/dev/null
    or return 1
    set -q argv[1]
    and echo $argv[1]
end

function __minsec_needs_command
    not __minsec_subcommand >/dev/null
end

# True if the subcommand on the command line is one of the arguments.
function __minsec_using
    set -l cmd (__minsec_subcommand)
    or return 1
    contains -- $cmd $argv
end

# True if the current token is positional argument number $argv[1] of the
# subcommand. Option values are skipped using the union of all option specs.
function __minsec_positional
    set -l want $argv[1]
    set -l tokens (commandline -opc)
    set -e tokens[1]
    argparse -s c/config-dir= json h/help V/version -- $tokens 2>/dev/null
    or return 1
    set -e argv[1]
    argparse -i c/config-dir= json h/help q/quiet backend= ttl= n/last= all replay -- $argv 2>/dev/null
    or return 1
    test (count $argv) -eq (math $want - 1)
end

# Print --config-dir DIR from the command line so data queries look at the
# same configuration the user is about to operate on.
function __minsec_config_args
    set -l tokens (commandline -opc)
    set -l i 2
    while test $i -le (count $tokens)
        switch $tokens[$i]
            case -c --config-dir
                if set -q tokens[(math $i + 1)]
                    printf '%s\n' --config-dir $tokens[(math $i + 1)]
                end
                return
            case '--config-dir=*'
                printf '%s\n' --config-dir (string replace -- '--config-dir=' '' $tokens[$i])
                return
        end
        set i (math $i + 1)
    end
end

# Filter names with descriptions; $argv[1] selects all, enabled, or disabled.
function __minsec_filters
    set -l cmd (commandline -opc)[1]
    command $cmd (__minsec_config_args) filters 2>/dev/null | awk -v want=$argv[1] '
        $1 == "*" { if (want == "disabled") next; n = $2; s = 3 }
        $1 != "*" { if (want == "enabled") next; n = $1; s = 2 }
        { d = ""; for (i = s; i <= NF; i++) d = d (i > s ? " " : "") $i; print n "\t" d }'
end

# Active bans as nft-style addresses and networks.
function __minsec_bans
    set -l cmd (commandline -opc)[1]
    command $cmd (__minsec_config_args) list 2>/dev/null | awk '{ print $1 }'
end

set -l subcommands daemon check inspect test status list ban unban filters enable disable events help

complete -c minsec -f
complete -c minsec -s c -l config-dir -x -a '(__fish_complete_directories)' -d 'Configuration directory'
complete -c minsec -l json -d 'Machine-readable JSON output'
complete -c minsec -s h -l help -d 'Print help'
complete -c minsec -n __minsec_needs_command -s V -l version -d 'Print version'

complete -c minsec -n __minsec_needs_command -a daemon -d 'Run the daemon in the foreground'
complete -c minsec -n __minsec_needs_command -a check -d 'Validate configuration and compile filters'
complete -c minsec -n __minsec_needs_command -a inspect -d 'Inspect merged configuration, files, filters, and effective policy'
complete -c minsec -n __minsec_needs_command -a test -d 'Run a filter over a log file (or stdin) and show what would match'
complete -c minsec -n __minsec_needs_command -a status -d 'Daemon status'
complete -c minsec -n __minsec_needs_command -a list -d 'List active bans'
complete -c minsec -n __minsec_needs_command -a ban -d 'Ban an address or network'
complete -c minsec -n __minsec_needs_command -a unban -d 'Remove a ban'
complete -c minsec -n __minsec_needs_command -a filters -d 'List built-in and custom filters'
complete -c minsec -n __minsec_needs_command -a enable -d 'Enable a filter'
complete -c minsec -n __minsec_needs_command -a disable -d 'Disable a filter'
complete -c minsec -n __minsec_needs_command -a events -d 'Print the event log'
complete -c minsec -n __minsec_needs_command -a help -d 'Print help for a subcommand'

complete -c minsec -n '__minsec_using daemon' -l backend -x -a 'nft null exec' -d 'Override the backend'
complete -c minsec -n '__minsec_using daemon' -l replay -d 'Read existing log files from the beginning instead of the end'
complete -c minsec -n '__minsec_using check' -l all -d 'Compile every discovered filter, including disabled custom filters'
complete -c minsec -n '__minsec_using test' -s q -l quiet -d 'Only print a summary'
complete -c minsec -n '__minsec_using test; and __minsec_positional 1' -a '(__minsec_filters all)'
complete -c minsec -n '__minsec_using test; and __minsec_positional 2' -F
complete -c minsec -n '__minsec_using ban' -l ttl -x -d 'Ban duration (e.g. 1h, 2d)'
complete -c minsec -n '__minsec_using unban; and __minsec_positional 1' -a '(__minsec_bans)'
complete -c minsec -n '__minsec_using enable; and __minsec_positional 1' -a '(__minsec_filters disabled)'
complete -c minsec -n '__minsec_using disable; and __minsec_positional 1' -a '(__minsec_filters enabled)'
complete -c minsec -n '__minsec_using events' -s n -l last -x -d 'Number of events to print'
complete -c minsec -n '__minsec_using help; and __minsec_positional 1' -a "$subcommands"
