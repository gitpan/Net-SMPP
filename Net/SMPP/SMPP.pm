# Net::SMPP.pm  -  SMPP over TCP, pure perl implementation
# 12.3.2001, Sampo Kellomaki <sampo@iki.fi>

### The comments often refer to sections of the following document
###   Short Message Peer to Peer Protocol Specification v3.4,
###   12-Oct-1999, Issue 1.2 (from www.smpp.org)

package Net::SMPP;

require 5.005;
use strict;
use warnings;
use Socket;
use IO::Socket;
use IO::Socket::INET;

use vars qw(@ISA $VERSION %default);
@ISA = qw(IO::Socket::INET);
$VERSION = '0.01';

use constant Transmitter => 1;  # SMPP transmitter mode of operation
use constant Receiver    => 2;  #      receiver mode of operation
use constant Transciver  => 3;  #      both

### Command IDs

use constant CMD_generic_nack          => 0x80000000;
use constant CMD_bind_receiver         => 0x00000001;
use constant CMD_bind_receiver_resp    => 0x80000001;
use constant CMD_bind_transmitter      => 0x00000002;
use constant CMD_bind_transmitter_resp => 0x80000002;
use constant CMD_query                 => 0x00000003;
use constant CMD_query_resp            => 0x80000003;
use constant CMD_submit                => 0x00000004;
use constant CMD_submit_resp           => 0x80000004;
use constant CMD_deliver               => 0x00000005;
use constant CMD_deliver_resp          => 0x80000005;
use constant CMD_unbind                => 0x00000006;
use constant CMD_unbind_resp           => 0x80000006;
use constant CMD_replace               => 0x00000007;
use constant CMD_replace_resp          => 0x80000007;
use constant CMD_cancel                => 0x00000008;
use constant CMD_cancel_resp           => 0x80000008;
use constant CMD_bind_transciever      => 0x00000009;
use constant CMD_bind_transciever_resp => 0x80000009;
use constant CMD_outbind               => 0x0000000b;
use constant CMD_enquire_link          => 0x00000015;
use constant CMD_enquire_link_resp     => 0x80000015;
use constant CMD_submit_multi          => 0x00000021;
use constant CMD_submit_multi_resp     => 0x80000021;
use constant CMD_alert_notification    => 0x00000102;
use constant CMD_data                  => 0x00000103;
use constant CMD_data_resp             => 0x80000103;

@command_name = qw( nack bind_receiver bind_transmitter
		    query submit deliver unbind replace cancel
		    bind_transciever resA outbind
		    resB resC resD resE resF res10 res11 res12 res13 res14
		    enquire_link r16 r17 r18 r19 f1a r1b r1c r1d r1e r1f r20
		    submit_multi
		    );



### Type of Number constants, see section 5.2.5, p. 117

use constant TON_unknown           => 0x00;
use constant TON_international     => 0x01;
use constant TON_national          => 0x02;
use constant TON_network_specific  => 0x03;
use constant TON_subscriber_number => 0x04;
use constant TON_alphanumeric      => 0x05;
use constant TON_abbreviated       => 0x06;

### Number plan indicators, sec 5.2.6, p. 118

use constant NPI_unknown     => 0x00;
use constant NPI_isdn        => 0x01;  # E163/E164
use constant NPI_data        => 0x03;  # X.121
use constant NPI_telex       => 0x04;  # F.69
use constant NPI_land_mobile => 0x06;  # E.212
use constant NPI_national    => 0x08;
use constant NPI_private     => 0x09;
use constant NPI_ERMES       => 0x0a;
use constant NPI_internet    => 0x0e;  # IP
use constant NPI_wap         => 0x12;  # WAP client id

###
### pack templates for mandatory parts of various PDUs
###

use constant Header => 'NNNN';     # ($length, $cmd, $status, $seq)  (3.2)
use constant OptParam => 'nn/a*';  # ($tag, $len, $data) (3.2.4.1)

### All bind operations have same PDU format (4.1)
use constant Bind => 'ZZZCCCZ';    # sys_id, pw, sys_type, if_ver, ton, npi, ar
use constant BindResp => 'Z';      # sys_id
use constant Outbind => 'ZZ';      # sys_id, pw (4.1.7.1)

use constant Unbind => '';         # no mandatory fields (4.2.1)
use constant UnbindResp => '';     # no mandatory fields (4.2.2)
use constant GenericNACK => '';    # no mandatory fields (4.3.1)
use constant EnquireLink => '';    # no mandatory fields (4.11.1)
use constant EnquireLinkResp => '';    # no mandatory fields (4.11.2)

### submit (4.4.1), deliver (4.6.1) (both use same PDU format), p.59
#
# serv_type1, saddr_ton2, saddr_npi3, saddr4,
#             daddr_ton5, daddr_npi6, daddr7, 
#   esm_class8, proto_id9, prio_flag10, sched11, validity12,
#   reg_deliv13, repl_if_present14, coding15, canned_id16,
#   length17, data18
#                                1
#                       12345678901234567 8
use constant Submit => 'ZCCZCCZCCCZZCCCCC/a';
use constant SubmitResp => 'Z';  # message_id (4.4.2)

### submit_multi (4.5) not implemented

### data (4.7.1), p.87
# 1 - service_type
# 2 - source_addr_ton
# 3 - source_addr_npi
# 4 - source_addr
# 5 - dest_addr_ton
# 6 - dest_addr_npi
# 7 - destination_addr
# 8 - esm_class
# 9 - registered_delivery
# 10 - data_coding
#                     1234567890
use constant Data => 'ZCCZCCZCCC'; # serv_type, src_ton, npi, addr, dst_t, n, a
use constant DataResp => 'Z';      # message_id

### query (4.8.1), p.95
# 1 - message_id
# 2 - source_addr_ton
# 3 - source_addr_npi
# 4 - source_addr
#                      1234
use constant Query => 'ZCCZ';
use constant QueryResp => 'ZZCC'; # message_id, final_date, message_state, error_code

### cancel (4.9.1), p.98
# 1 - service_type
# 2 - message_id
# 3 - source_addr_ton
# 4 - source_addr_npi
# 5 - source_addr
# 6 - dest_addr_ton
# 7 - dest_addr_npi
# 8 - destination_addr
#                       12345678
use constant Cancel => 'ZZCCZCCZ';
use constant CancelResp => '';    # no mandatory fields (4.9.2)

### replace (4.10.1), p.102
# 1 - message_id
# 2 - source_addr_ton
# 3 - source_addr_npi
# 4 - source_addr
# 5 - scheduled_delivery_time
# 6 - validity_period
# 7 - registered_delivery
# 8 - sm_default_msg_id
# 9 - sm_length
# 10 - short_message
#                        123456789 0
use constant Replace => 'ZCCZZZCCC/a';
use constant ReplaceResp => '';   # no mandatory fields (4.10.2)

### alert_notification (4.12.1), p.108
# 1 - source_addr_ton
# 2 - source_addr_npi
# 3 - source_addr
# 4 - esme_addr_ton
# 5 - esme_addr_npi
# 6 - esme_addr
#                                  123456
use constant AlertNotification => 'CCZCCZ';

### Default values for bind parameters
### For interpretation of these parameters refer to
### sections 4.1 (p.51) and 5.2 (p. 116).

use constant Default => {
	    port => 2255,        # TCP port
	    timeout => 120,      # Connection establishment timeout
	    mode => Transciever, # Chooses type of bind
	    system_id => '',     # 5.2.1, usually needs to be supplied
	    password => '',      # 5.2.2
	    system_type => '',   # 5.2.3, often optional, leave empty
	    interface_version => 0x34,  # 5.2.4
	    addr_ton => 0x00,    # 5.2.5  type of number
	    addr_npi => 0x00,    # 5.2.6  numbering plan indicator
	    address_range => '', # 5.2.7  regular expression matching numbers
	    };

sub new {
    my $me = shift;
    my $type = ref($me) || $me;
    my $host = shift if @_ % 2;  # host need not be tagged
    my %arg = @_;
    
    for my $a (keys %{Default}) {
	$obj->{$a} = exists $arg{$a} ? $arg{$a} : Default->{$a};
    }
    
    my $obj = $type->SUPER::new(PeerAddr => $host,
				PeerPort => $obj->{port},
				Proto    => 'tcp',
				Timeout  => $obj->{timeout}) or return undef;
    $obj->autoflush(1);
    $obj->debug(exists $arg{debug} ? $arg{debug} : undef);

}

1;
__END__
# Below is stub documentation for your module. You better edit it!

=head1 NAME

Net::SMPP - pure Perl implementation of SMPP 3.4 over TCP

=head1 SYNOPSIS

  use Net::SMPP;
  $smpp = new Net::SMPP($host, port=>$port,
			system_id => 'yourusername',
			password  => 'secret',
			) or die;

=head1 DESCRIPTION

Implements Short Message Peer to Peer protocol, which is frequently used to
pass short messages between mobile operators implementing short message
service (SMS). This is applicable to both europena GSM and american CDMA
systems.

Despite its name, SMPP protocol defines a client and server (often
called SMSC in the mobile operator world). Client always initiates the
TCP connection and does I<bind> to log in. After binding, a series of
request response pairs, called PDUs (protocol data units) is
exchanged. Request can be initiated by either end (hence
"peer-to-peer"?) and the other end reponds. Requests are numbered
with a sequence number and each response has corresponding sequence
number. This allows several requests to be pending at the same
time. Conceptually this is similar to IMAP.

Typical client:

  use Net:SMPP;
  $smpp = new Net::SMPP('smsc.foo.net', Port=>2255) or die;
  ***

Typical server, run from inetd:

  ***

=head2 EXPORT

None by default.

=head1 AUTHOR

Sampo Kellomaki <sampo@iki.fi>

=head1 SEE ALSO

www.smpp.org
Short Message Peer to Peer Protocol Specification v3.4, 12-Oct-1999, Issue 1.2
perl(1).

=cut

