# Fish completion for minsec-sync. All values are static.

function __minsec_sync_subcommand
    set -l tokens (commandline -opc)
    set -e tokens[1]
    argparse -s c/config= dry-run h/help V/version -- $tokens 2>/dev/null
    or return 1
    set -q argv[1]
    and echo $argv[1]
end

function __minsec_sync_needs_command
    not __minsec_sync_subcommand >/dev/null
end

function __minsec_sync_using
    set -l cmd (__minsec_sync_subcommand)
    or return 1
    contains -- $cmd $argv
end

complete -c minsec-sync -f
complete -c minsec-sync -s c -l config -r -F -d 'Configuration file'
complete -c minsec-sync -l dry-run -d 'Print nft scripts instead of applying them'
complete -c minsec-sync -s h -l help -d 'Print help'
complete -c minsec-sync -n __minsec_sync_needs_command -s V -l version -d 'Print version'

complete -c minsec-sync -n __minsec_sync_needs_command -a enroll -d 'Generate a key (first run) and enroll with the server'
complete -c minsec-sync -n __minsec_sync_needs_command -a report -d 'Submit new automatic bans from the events log'
complete -c minsec-sync -n __minsec_sync_needs_command -a pull -d 'Fetch the crowd blocklist into the crowd4/crowd6 nftables sets'
complete -c minsec-sync -n __minsec_sync_needs_command -a run -d 'Report then pull; enrolls first if needed'
complete -c minsec-sync -n __minsec_sync_needs_command -a status -d 'Show enrollment, cursor, and feed state'
complete -c minsec-sync -n __minsec_sync_needs_command -a help -d 'Print help for a subcommand'
complete -c minsec-sync -n '__minsec_sync_using help' -a 'enroll report pull run status help'
