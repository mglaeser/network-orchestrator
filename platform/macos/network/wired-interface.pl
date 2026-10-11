#!/usr/bin/perl
package WiredInterface;
use strict;
use warnings;
use IPC::Open3 qw(open3);
use IO::Select;
use Symbol qw(gensym);

# One read-only selector for the existing forwarding/discovery owners. The IP
# remains a separately admitted DHCP/router decision; no address is assigned here.
sub valid_ipv4 {
    my ($ip) = @_;
    return 0 unless defined($ip) && $ip =~ /\A(?:0|[1-9][0-9]{0,2})(?:\.(?:0|[1-9][0-9]{0,2})){3}\z/;
    return !grep { $_ > 255 } split /\./, $ip;
}

sub valid_netmask {
    my ($mask) = @_;
    my $value;
    if ($mask =~ /\A0x[0-9a-fA-F]{8}\z/) { $value = hex($mask); }
    elsif (valid_ipv4($mask)) { $value = unpack("N", pack("C4", split /\./, $mask)); }
    else { return 0; }
    my $inverse = 0xffffffff ^ $value;
    return ($inverse & ($inverse + 1)) == 0;
}

sub hardware_ports {
    my ($text) = @_;
    die "malformed hardware inventory\n" if !defined($text) || $text =~ /\0|\r/;
    my %ports;
    my @record;
    my $vlan = 0;
    my $finish = sub {
        return unless @record;
        die "malformed hardware inventory record\n" unless @record == 3
            && $record[0] =~ /\AHardware Port: ([^\n]+)\z/;
        my $label = $1;
        die "malformed hardware device\n" unless $record[1] =~ /\ADevice: ([A-Za-z][A-Za-z0-9_.-]*)\z/;
        my $device = $1;
        die "malformed hardware address\n" unless $record[2] =~ /\AEthernet Address: ((?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2})\z/;
        die "duplicate hardware device\n" if exists $ports{$device};
        $ports{$device} = { label => $label, mac => lc($1) };
        @record = ();
    };
    for my $line (split /\n/, $text) {
        if ($line eq '') { $finish->(); next; }
        if ($line eq 'VLAN Configurations') { $finish->(); $vlan = 1; next; }
        if ($vlan) {
            # An unexpected inventory format is not permission to select a link.
            die "unexpected VLAN hardware inventory\n" unless $line =~ /\A=+\z/;
            next;
        }
        if ($line =~ /\AHardware Port: / && @record) { $finish->(); }
        push @record, $line;
    }
    $finish->();
    die "empty hardware inventory\n" unless keys %ports;
    return \%ports;
}

sub interfaces {
    my ($text) = @_;
    die "malformed interface inventory\n" if !defined($text) || $text =~ /\0|\r/;
    my %interfaces;
    my $current;
    for my $line (split /\n/, $text) {
        next if $line eq '';
        if ($line !~ /\A\s/) {
            die "malformed interface header\n" unless $line =~ /\A([A-Za-z][A-Za-z0-9_.-]*): flags=[0-9a-fA-F]+<([^>]*)> mtu [0-9]+(?: .*)?\z/;
            my ($name, $flags) = ($1, $2);
            die "duplicate interface record\n" if exists $interfaces{$name};
            $current = { flags => { map { $_ => 1 } split /,/, $flags }, addresses => [] };
            $interfaces{$name} = $current;
            next;
        }
        die "orphan interface detail\n" unless $current;
        if ($line =~ /\A\s+inet\b/) {
            die "malformed IPv4 interface address\n" unless $line =~ /\A\s+inet ([^ ]+) netmask ([^ ]+)(?: .*)?\z/
                && valid_ipv4($1) && valid_netmask($2);
            push @{$current->{addresses}}, $1;
        } elsif ($line =~ /\A\s+(ether|media|status)(?:\s|:)/) {
            my $kind = $1;
            die "duplicate interface $kind\n" if exists $current->{$kind};
            if ($kind eq 'ether') {
                die "malformed interface MAC address\n" unless $line =~ /\A\s+ether ((?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2})\s*\z/;
                $current->{$kind} = lc($1);
            } else {
                die "malformed interface $kind\n" unless $line =~ /\A\s+$kind: (\S(?:.*\S)?)\s*\z/;
                $current->{$kind} = $1;
            }
        }
    }
    die "empty interface inventory\n" unless keys %interfaces;
    return \%interfaces;
}

sub resolve {
    my ($ip, $hardware_text, $interface_text) = @_;
    die "expected one canonical unicast IPv4 address\n" unless valid_ipv4($ip)
        && $ip !~ /\A(?:0|127|22[4-9]|2[3-5][0-9])\./;
    my $hardware = hardware_ports($hardware_text);
    my $interfaces = interfaces($interface_text);
    my @owners;
    for my $name (sort keys %$interfaces) {
        push @owners, ($name) x grep { $_ eq $ip } @{$interfaces->{$name}{addresses}};
    }
    die "address $ip is not present on any interface\n" unless @owners;
    die "address $ip is duplicated; refusing ambiguous LAN ownership\n" unless @owners == 1;
    my $name = $owners[0];
    my $link = $interfaces->{$name};
    die "address $ip is not on an inventoried physical Ethernet interface\n"
        unless $name =~ /\Aen[0-9]+\z/ && exists $hardware->{$name};
    my $port = $hardware->{$name};
    die "address $ip belongs to wireless, bridge or virtual hardware\n"
        if $port->{label} =~ /wi-?fi|wireless|airport|bridge|vpn|virtual|bluetooth/i
        || ($port->{label} =~ /thunderbolt/i && $port->{label} !~ /ethernet/i);
    die "physical Ethernet hardware address is unavailable or invalid\n"
        if $port->{mac} eq '00:00:00:00:00:00'
            || $port->{mac} eq '02:00:00:00:00:00'
            || (hex(substr($port->{mac}, 0, 2)) & 1);
    # macOS 27 can redact ifconfig's link MAC in a child process group while
    # networksetup still reports the physical inventory. This exact sentinel
    # is unavailable link evidence, not a contradictory MAC. The remaining
    # physical-device, unique-IP, active-link and media gates still apply; no
    # permission bypass or alternative MAC-discovery mechanism is introduced.
    die "physical and active-interface Ethernet identities disagree\n"
        unless defined($link->{ether}) && ($link->{ether} eq $port->{mac}
            || $link->{ether} eq '02:00:00:00:00:00');
    die "wired interface $name is not active and up\n"
        unless ($link->{status} // '') eq 'active' && $link->{flags}{UP}
            && $link->{flags}{RUNNING} && $link->{flags}{BROADCAST}
            && !$link->{flags}{LOOPBACK} && !$link->{flags}{POINTOPOINT};
    # Link negotiation is evidence of cable Ethernet, not a 1-Gbit speed gate.
    # A gigabit adapter negotiating 100baseTX must not disable working DNS.
    my $copper = qr/(?:10|100|1000|2500|5000|10G|25G|40G|50G|100G)base-?(?:T|TX|T1)(?: <[a-z][a-z0-9-]*(?:,[a-z][a-z0-9-]*)*>)?/i;
    die "interface $name has no negotiated cable Ethernet media\n"
        unless ($link->{media} // '') =~ /\A(?:autoselect \($copper\)|$copper)\z/;
    return $name;
}

sub command_output {
    my (@command) = @_;
    my ($pid, $output, $error) = (undef, '', '');
    my $ok = eval {
        local %ENV = (PATH => '/usr/bin:/bin:/usr/sbin:/sbin', LC_ALL => 'C', LANG => 'C');
        local $SIG{ALRM} = sub { die "native inventory command timed out\n" };
        alarm 5;
        my ($input, $stdout, $stderr);
        $stderr = gensym;
        $pid = open3($input, $stdout, $stderr, @command);
        close $input;
        my $select = IO::Select->new($stdout, $stderr);
        my $stdout_fd = fileno($stdout);
        while ($select->count) {
            for my $handle ($select->can_read) {
                my $length = sysread($handle, my $buffer, 8192);
                die "cannot read native inventory\n" unless defined $length;
                if (!$length) { $select->remove($handle); close $handle; next; }
                if (fileno($handle) == $stdout_fd) { $output .= $buffer; }
                else { $error .= $buffer; }
                die "native inventory exceeded size limit\n" if length($output) + length($error) > 1048576;
            }
        }
        waitpid($pid, 0);
        my $status = $?;
        $pid = undef;
        die "native inventory command failed\n" if $status != 0 || length $error;
        alarm 0;
        1;
    };
    my $failure = $@;
    alarm 0;
    if (!$ok) {
        # Reap only this owned child before returning the error; WNOHANG can
        # leave a just-killed process unreaped. The outer managed process group
        # supplies the total deadline when this module is used by preflight.
        if (defined $pid) { kill 'KILL', $pid; waitpid($pid, 0); }
        die $failure;
    }
    return $output;
}

sub main {
    die "usage: wired-interface.pl IPV4\n" unless @ARGV == 1;
    # Reject invalid input before spawning either native read-only command.
    die "expected one canonical unicast IPv4 address\n" unless valid_ipv4($ARGV[0])
        && $ARGV[0] !~ /\A(?:0|127|22[4-9]|2[3-5][0-9])\./;
    print resolve($ARGV[0], command_output('/usr/sbin/networksetup', '-listallhardwareports'),
        command_output('/sbin/ifconfig', '-a')), "\n";
}

unless (caller) {
    my $ok = eval { main(); 1 };
    if (!$ok) { print STDERR 'wired-interface: ', $@; exit 1; }
}
1;
