package Gitolite::Triggers::ProxyExec;

# installation notes for ProxyExec.pm gitolite INPUT trigger:
# - copy ProxyExec.pm to gitolite/src/lib/Gitolite/Triggers/ProxyExec.pm
# - define extension in rc file ($ENV{HOME}/.gitolite.rc) before ENABLE => [ ...
#      NON_CORE => "
#          ProxyExec INPUT :: before Shell
#      ",
# - add 'ProxyExec', to ENABLE list in .gitolite.rc (near system admin stuff)

use Gitolite::Rc;
use Gitolite::Common;

sub input {
    return unless (exists $ENV{PROXYEXEC_UID});

    # discard 'gitolite' literal arg if provided; some proxyexec setups might
    # require gitolite commands be run as 'gitolite <command>' to be recognized
    shift @ARGV if (@ARGV && $ARGV[0] eq 'gitolite');

    # gitolite expects SSH_ORIGINAL_COMMAND to be set to command and args,
    # so set SSH_ORIGINAL_COMMAND to the parameters sent through proxyexec.
    # gitolite expects repo name to be surrounded by single quotes, so restore
    # the single quotes which were removed by proxyexec use of wordexp()
    $ARGV[1] = "'$ARGV[1]'"
      if (@ARGV >= 2
          && $ARGV[0] =~
               m/^(?:git-upload-pack|git-receive-pack|git-upload-archive)$/);
    $ENV{SSH_ORIGINAL_COMMAND} = "@ARGV";

    # gitolite expects username as only arg in @ARGV
    my $username = getpwuid($ENV{PROXYEXEC_UID})
      || _die "invalid user (uid $ENV{PROXYEXEC_UID})";
    @ARGV = ($username);
}

1;
