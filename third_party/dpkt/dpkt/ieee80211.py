# $Id: 80211.py 53 2008-12-18 01:22:57Z jon.oberheide $

"""IEEE 802.11."""

import dpkt, socket, struct

# Frame Types
MGMT_TYPE           = 0
CTL_TYPE            = 1
DATA_TYPE           = 2

# Frame Sub-Types
M_ASSOC_REQ         = 0
M_ASSOC_RESP        = 1
M_REASSOC_REQ       = 2
M_REASSOC_RESP      = 3
M_PROBE_REQ         = 4
M_PROBE_RESP        = 5
M_DISASSOC          = 10
M_AUTH              = 11
M_DEAUTH            = 12
M_BEACON            = 8
M_ATIM              = 9
C_BLOCK_ACK_REQ     = 8
C_BLOCK_ACK         = 9
C_PS_POLL           = 10
C_RTS               = 11
C_CTS               = 12
C_ACK               = 13
C_CF_END            = 14
C_CF_END_ACK        = 15
D_DATA              = 0
D_DATA_CF_ACK       = 1
D_DATA_CF_POLL      = 2
D_DATA_CF_ACK_POLL  = 3
D_NULL              = 4
D_CF_ACK            = 5
D_CF_POLL           = 6
D_CF_ACK_POLL       = 7
D_QOS_DATA          = 8
D_QOS_CF_ACK        = 9
D_QOS_CF_POLL       = 10
D_QOS_CF_ACK_POLL   = 11
D_QOS_NULL          = 12
D_QOS_CF_POLL_EMPTY = 14

TO_DS_FLAG          = 10
FROM_DS_FLAG        = 1
INTER_DS_FLAG       = 11

# Bitshifts for Frame Control
_VERSION_MASK       = 0x0300
_TYPE_MASK          = 0x0c00
_SUBTYPE_MASK       = 0xf000
_TO_DS_MASK         = 0x0001
_FROM_DS_MASK       = 0x0002
_MORE_FRAG_MASK     = 0x0004
_RETRY_MASK         = 0x0008
_PWR_MGT_MASK       = 0x0010
_MORE_DATA_MASK     = 0x0020
_WEP_MASK           = 0x0040
_ORDER_MASK         = 0x0080
_VERSION_SHIFT      = 8
_TYPE_SHIFT         = 10
_SUBTYPE_SHIFT      = 12
_TO_DS_SHIFT        = 0
_FROM_DS_SHIFT      = 1
_MORE_FRAG_SHIFT    = 2
_RETRY_SHIFT        = 3
_PWR_MGT_SHIFT      = 4
_MORE_DATA_SHIFT    = 5
_WEP_SHIFT          = 6
_ORDER_SHIFT        = 7

# IEs
IE_SSID    = 0
IE_RATES   = 1
IE_FH      = 2
IE_DS      = 3
IE_CF      = 4
IE_TIM     = 5
IE_IBSS    = 6
IE_HT_CAPA = 45
IE_ESR     = 50
IE_HT_INFO = 61


class IEEE80211(dpkt.Packet):
    __hdr__ = (
        ('framectl', 'H', 0),
        ('duration', 'H', 0)
        )

    def _get_version(self): return (self.framectl & _VERSION_MASK) >> _VERSION_SHIFT
    def _set_version(self, val): self.framectl = (val << _VERSION_SHIFT) | (self.framectl & ~_VERSION_MASK)
    def _get_type(self): return (self.framectl & _TYPE_MASK) >> _TYPE_SHIFT
    def _set_type(self, val): self.framectl = (val << _TYPE_SHIFT) | (self.framectl & ~_TYPE_MASK)
    def _get_subtype(self): return (self.framectl & _SUBTYPE_MASK) >> _SUBTYPE_SHIFT
    def _set_subtype(self, val): self.framectl = (val << _SUBTYPE_SHIFT) | (self.framectl & ~_SUBTYPE_MASK)
    def _get_to_ds(self): return (self.framectl & _TO_DS_MASK) >> _TO_DS_SHIFT
    def _set_to_ds(self, val): self.framectl = (val << _TO_DS_SHIFT) | (self.framectl & ~_TO_DS_MASK)
    def _get_from_ds(self): return (self.framectl & _FROM_DS_MASK) >> _FROM_DS_SHIFT
    def _set_from_ds(self, val): self.framectl = (val << _FROM_DS_SHIFT) | (self.framectl & ~_FROM_DS_MASK)
    def _get_more_frag(self): return (self.framectl & _MORE_FRAG_MASK) >> _MORE_FRAG_SHIFT
    def _set_more_frag(self, val): self.framectl = (val << _MORE_FRAG_SHIFT) | (self.framectl & ~_MORE_FRAG_MASK)
    def _get_retry(self): return (self.framectl & _RETRY_MASK) >> _RETRY_SHIFT
    def _set_retry(self, val): self.framectl = (val << _RETRY_SHIFT) | (self.framectl & ~_RETRY_MASK)
    def _get_pwr_mgt(self): return (self.framectl & _PWR_MGT_MASK) >> _PWR_MGT_SHIFT
    def _set_pwr_mgt(self, val): self.framectl = (val << _PWR_MGT_SHIFT) | (self.framectl & ~_PWR_MGT_MASK)
    def _get_more_data(self): return (self.framectl & _MORE_DATA_MASK) >> _MORE_DATA_SHIFT
    def _set_more_data(self, val): self.framectl = (val << _MORE_DATA_SHIFT) | (self.framectl & ~_MORE_DATA_MASK)
    def _get_wep(self): return (self.framectl & _WEP_MASK) >> _WEP_SHIFT
    def _set_wep(self, val): self.framectl = (val << _WEP_SHIFT) | (self.framectl & ~_WEP_MASK)
    def _get_order(self): return (self.framectl & _ORDER_MASK) >> _ORDER_SHIFT
    def _set_order(self, val): self.framectl = (val << _ORDER_SHIFT) | (self.framectl & ~_ORDER_MASK)

    version = property(_get_version, _set_version)
    type = property(_get_type, _set_type)
    subtype = property(_get_subtype, _set_subtype)
    to_ds = property(_get_to_ds, _set_to_ds)
    from_ds = property(_get_from_ds, _set_from_ds)
    more_frag = property(_get_more_frag, _set_more_frag)
    retry = property(_get_retry, _set_retry)
    pwr_mgt = property(_get_pwr_mgt, _set_pwr_mgt)
    more_data = property(_get_more_data, _set_more_data)
    wep = property(_get_wep, _set_wep)
    order = property(_get_order, _set_order)

    def unpack_ies(self, buf):
        self.ies = []

        ie_decoder = {
           IE_SSID:     ('ssid',    self.IE),
           IE_RATES:    ('rate',    self.IE),
           IE_FH:       ('fh',      self.FH),
           IE_DS:       ('ds',      self.DS),
           IE_CF:       ('cf',      self.CF),
           IE_TIM:      ('tim',     self.TIM),
           IE_IBSS:     ('ibss',    self.IBSS),
           IE_HT_CAPA:  ('ht_capa', self.IE),
           IE_ESR:      ('esr',     self.IE),
           IE_HT_INFO:  ('ht_info', self.IE)
        }
 
        # each IE starts with an ID and a length
        while len(buf):
            ie_id = struct.unpack('B',(buf[0]))[0]
            try:
               parser = ie_decoder[ie_id][1]
               name = ie_decoder[ie_id][0] 
            except KeyError:
               parser = self.IE
               name = 'ie_' + str(ie_id)
            ie = parser(buf)

            ie.data = buf[2:2+ie.len]
            setattr(self, name, ie)
            self.ies.append(ie)
            buf = buf[2+ie.len:]

    class Capability:
        def __init__(self, field):
            self.ess = field & 1
            self.ibss = (field >> 1) & 1
            self.cf_poll = (field >> 2) & 1
            self.cf_poll_req = (field >> 3) & 1
            self.privacy = (field >> 4) & 1
            self.short_preamble = (field >> 5) & 1
            self.pbcc = (field >> 6) & 1
            self.hopping = (field >> 7) & 1
            self.spec_mgmt = (field >> 8) & 1
            self.qos = (field >> 9) & 1
            self.short_slot = (field >> 10) & 1
            self.apsd = (field >> 11) & 1
            self.dsss = (field >> 13) & 1
            self.delayed_blk_ack = (field >> 14) & 1
            self.imm_blk_ack = (field >> 15) & 1

    def unpack(self, buf):
        dpkt.Packet.unpack(self, buf)
        self.data = buf[self.__hdr_len__:]

        m_decoder = {
            M_BEACON:       ('beacon',      self.Beacon),
            M_ASSOC_REQ:    ('assoc_req',   self.Assoc_Req),
            M_ASSOC_RESP:   ('assoc_resp',  self.Assoc_Resp),
            M_DISASSOC:     ('diassoc',     self.Disassoc),
            M_REASSOC_REQ:  ('reassoc_req', self.Reassoc_Req),
            M_REASSOC_RESP: ('reassoc_resp',self.Assoc_Resp),
            M_AUTH:         ('auth',        self.Auth),
            M_PROBE_RESP:   ('probe_resp',  self.Beacon),
            M_DEAUTH:       ('deauth',      self.Deauth)
        }

        c_decoder = {
            C_RTS:          ('rts',         self.RTS),
            C_CTS:          ('cts',         self.CTS),
            C_ACK:          ('ack',         self.ACK),
            C_BLOCK_ACK_REQ:('bar',         self.BlockAckReq),
            C_BLOCK_ACK:    ('back',        self.BlockAck)
        }

        d_dsData = {
            0               :   self.Data,
            FROM_DS_FLAG    :   self.DataFromDS,
            TO_DS_FLAG      :   self.DataToDS,
            INTER_DS_FLAG   :   self.DataInterDS
        }


        # For now decode everything with DATA. Haven't checked about other QoS
        # additions
        d_decoder = {
            # modified the decoder to consider the ToDS and FromDS flags
            # Omitting the 11 case for now
            D_DATA:         ('data_frame',  d_dsData),
            D_NULL:         ('data_frame',  d_dsData),
            D_QOS_DATA:     ('data_frame',  d_dsData),
            D_QOS_NULL:     ('data_frame',  d_dsData)
        }

        decoder = {
            MGMT_TYPE:m_decoder,
            CTL_TYPE:c_decoder,
            DATA_TYPE:d_decoder
        }

        if self.type == MGMT_TYPE:
            self.mgmt = self.MGMT_Frame(self.data)
            self.data = self.mgmt.data
            if self.subtype == M_PROBE_REQ:
                self.unpack_ies(self.data)
                return
            if self.subtype == M_ATIM:
                return

        try:
            parser = decoder[self.type][self.subtype][1]
            name = decoder[self.type][self.subtype][0]
        except KeyError:
            print "Key error:", self.type, self.subtype
            return

        if self.type == DATA_TYPE:
            # need to grab the ToDS/FromDS info
            parser = parser[self.to_ds*10+self.from_ds]
        
        if self.type == MGMT_TYPE:
            field = parser(self.mgmt.data)
        else:
            field = parser(self.data)
            self.data = field
    
        setattr(self, name, field)

        if self.type == MGMT_TYPE:
            self.ies = self.unpack_ies(field.data)
            if self.subtype == M_BEACON or self.subtype == M_ASSOC_RESP or\
                self.subtype == M_ASSOC_REQ or self.subtype == M_REASSOC_REQ:
                self.capability = self.Capability(socket.ntohs(field.capability))

        if self.type == DATA_TYPE and self.subtype == D_QOS_DATA:
            self.qos_data = self.QoS_Data(field.data)
            field.data = self.qos_data.data
        
        self.data = field.data

    class BlockAckReq(dpkt.Packet):
        __hdr__ = (
            ('ctl', 'H', 0),
            ('seq', 'H', 0),
            )

    class BlockAck(dpkt.Packet):
        __hdr__ = (
            ('ctl', 'H', 0),
            ('seq', 'H', 0),
            ('bmp', '128s', '\x00' *128)
            )

    class RTS(dpkt.Packet):
        __hdr__ = (
            ('dst', '6s', '\x00' * 6),
            ('src', '6s', '\x00' * 6)
            )

    class CTS(dpkt.Packet):
        __hdr__ = (
            ('dst', '6s', '\x00' * 6),
            )

    class ACK(dpkt.Packet):
        __hdr__ = (
            ('dst', '6s', '\x00' * 6),
            )

    class MGMT_Frame(dpkt.Packet):
        __hdr__ = (
            ('dst', '6s', '\x00' *6),
            ('src', '6s', '\x00' *6),
            ('bssid', '6s', '\x00' *6),
            ('frag_seq', 'H', 0)
            )

    class Beacon(dpkt.Packet):
        __hdr__ = (
            ('timestamp', 'Q', 0),
            ('interval', 'H', 0),
            ('capability', 'H', 0)
            )

    class Disassoc(dpkt.Packet):
        __hdr__ = (
            ('reason', 'H', 0),
            )
    
    class Assoc_Req(dpkt.Packet):
        __hdr__ = (
            ('capability', 'H', 0),
            ('interval', 'H', 0)
            )
    
    class Assoc_Resp(dpkt.Packet):
        __hdr__ = (
            ('capability', 'H', 0),
            ('status', 'H', 0),
            ('aid', 'H', 0)
            )
    
    class Reassoc_Req(dpkt.Packet):
        __hdr__ = (
            ('capability', 'H', 0),
            ('interval', 'H', 0),
            ('current_ap', '6s', '\x00'*6)
            )

    # This obviously doesn't support any of AUTH frames that use encryption
    class Auth(dpkt.Packet):
        __hdr__ = (
            ('algorithm', 'H', 0),
            ('auth_seq', 'H', 0),
            )

    class Deauth(dpkt.Packet):
        __hdr__ = (
            ('reason', 'H', 0),
            )

    class Data(dpkt.Packet):
        __hdr__ = (
            ('dst', '6s', '\x00'*6),
            ('src', '6s', '\x00'*6),
            ('bssid', '6s', '\x00'*6),
            ('frag_seq', 'H', 0)
            )


    class DataFromDS(dpkt.Packet):
        __hdr__ = (
            ('dst', '6s', '\x00'*6),
            ('bssid', '6s', '\x00'*6),
            ('src', '6s', '\x00'*6),
            ('frag_seq', 'H', 0)
            )
    

    class DataToDS(dpkt.Packet):
        __hdr__ = (
            ('bssid', '6s', '\x00'*6),
            ('src', '6s', '\x00'*6),
            ('dst', '6s', '\x00'*6),
            ('frag_seq', 'H', 0)
            )

    class DataInterDS(dpkt.Packet):
        __hdr__ = (
            ('dst', '6s', '\x00'*6),
            ('src', '6s', '\x00'*6),
            ('da', '6s', '\x00'*6),
            ('frag_seq', 'H', 0),
            ('sa', '6s', '\x00'*6)
            )

    class QoS_Data(dpkt.Packet):
        __hdr__ = (
            ('control', 'H', 0),
            )

    class IE(dpkt.Packet):
        __hdr__ = (
            ('id', 'B', 0),
            ('len', 'B', 0)
            )
        def unpack(self, buf):        
            dpkt.Packet.unpack(self, buf)
            self.info = buf[2:self.len+ 2]
  
    class FH(dpkt.Packet):
        __hdr__ = (
            ('id', 'B', 0),
            ('len', 'B', 0),
            ('tu', 'H', 0),
            ('hopset', 'B', 0),
            ('hoppattern', 'B', 0),
            ('hopindex', 'B', 0)
            )
       
    class DS(dpkt.Packet):
        __hdr__ = (
            ('id', 'B', 0),
            ('len', 'B', 0),
            ('ch', 'B', 0)
            )

    class CF(dpkt.Packet):
        __hdr__ = (
            ('id', 'B', 0),
            ('len', 'B', 0),
            ('count', 'B', 0),
            ('period', 'B', 0),
            ('max', 'H', 0),
            ('dur', 'H', 0)
            )
  
    class TIM(dpkt.Packet):
       __hdr__ = (
            ('id', 'B', 0),
            ('len', 'B', 0),
            ('count', 'B', 0),
            ('period', 'B', 0),
            ('ctrl', 'H', 0)
            )
       def unpack(self, buf):        
            dpkt.Packet.unpack(self, buf)
            self.bitmap = buf[5:self.len+ 2]
   
    class IBSS(dpkt.Packet):
       __hdr__ = (
            ('id', 'B', 0),
            ('len', 'B', 0),
            ('atim', 'H', 0) 
            )



if __name__ == '__main__':
    import unittest
    
    class IEEE80211TestCase(unittest.TestCase):
        def test_802211(self):
            s = '\xd4\x00\x00\x00\x00\x12\xf0\xb6\x1c\xa4'
            ieee = IEEE80211(s)
            self.failUnless(ieee.version == 0)
            self.failUnless(ieee.type == CTL_TYPE)
            self.failUnless(ieee.subtype == C_ACK)
            self.failUnless(ieee.to_ds == 0)
            self.failUnless(ieee.from_ds == 0)
            self.failUnless(ieee.pwr_mgt == 0)
            self.failUnless(ieee.more_data == 0)
            self.failUnless(ieee.wep == 0)
            self.failUnless(ieee.order == 0)
            self.failUnless(ieee.ack.dst == '\x00\x12\xf0\xb6\x1c\xa4')
        
        def test_80211_beacon(self):
            s='\x80\x00\x00\x00\xff\xff\xff\xff\xff\xff\x00\x26\xcb\x18\x6a\x30\x00\x26\xcb\x18\x6a\x30\xa0\xd0\x77\x09\x32\x03\x8f\x00\x00\x00\x66\x00\x31\x04\x00\x04\x43\x41\x45\x4e\x01\x08\x82\x84\x8b\x0c\x12\x96\x18\x24\x03\x01\x01\x05\x04\x00\x01\x00\x00\x07\x06\x55\x53\x20\x01\x0b\x1a\x0b\x05\x00\x00\x6e\x00\x00\x2a\x01\x02\x2d\x1a\x6e\x18\x1b\xff\xff\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x30\x14\x01\x00\x00\x0f\xac\x04\x01\x00\x00\x0f\xac\x04\x01\x00\x00\x0f\xac\x01\x28\x00\x32\x04\x30\x48\x60\x6c\x36\x03\x51\x63\x03\x3d\x16\x01\x00\x05\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x85\x1e\x05\x00\x8f\x00\x0f\x00\xff\x03\x59\x00\x63\x73\x65\x2d\x33\x39\x31\x32\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x36\x96\x06\x00\x40\x96\x00\x14\x00\xdd\x18\x00\x50\xf2\x02\x01\x01\x80\x00\x03\xa4\x00\x00\x27\xa4\x00\x00\x42\x43\x5e\x00\x62\x32\x2f\x00\xdd\x06\x00\x40\x96\x01\x01\x04\xdd\x05\x00\x40\x96\x03\x05\xdd\x05\x00\x40\x96\x0b\x09\xdd\x08\x00\x40\x96\x13\x01\x00\x34\x01\xdd\x05\x00\x40\x96\x14\x05'
            ieee = IEEE80211(s)
            self.failUnless(ieee.version == 0)
            self.failUnless(ieee.type == MGMT_TYPE)
            self.failUnless(ieee.subtype == M_BEACON)
            self.failUnless(ieee.to_ds == 0)
            self.failUnless(ieee.from_ds == 0)
            self.failUnless(ieee.pwr_mgt == 0)
            self.failUnless(ieee.more_data == 0)
            self.failUnless(ieee.wep == 0)
            self.failUnless(ieee.order == 0)
            self.failUnless(ieee.mgmt.dst == '\xff\xff\xff\xff\xff\xff')
            self.failUnless(ieee.mgmt.src == '\x00\x26\xcb\x18\x6a\x30')
            self.failUnless(ieee.beacon.capability == 0x3104)
            self.failUnless(ieee.capability.privacy == 1)
            self.failUnless(ieee.ssid.data == 'CAEN')
            self.failUnless(ieee.rate.data == '\x82\x84\x8b\x0c\x12\x96\x18\x24')
            self.failUnless(ieee.ds.data == '\x01')
            self.failUnless(ieee.tim.data == '\x00\x01\x00\x00')

        def test_80211_data(self):
            s = '\x08\x09\x20\x00\x00\x26\xcb\x17\x3d\x91\x00\x16\x44\xb0\xae\xc6\x00\x02\xb3\xd6\x26\x3c\x80\x7e\xaa\xaa\x03\x00\x00\x00\x08\x00\x45\x00\x00\x28\x07\x27\x40\x00\x80\x06\x1d\x39\x8d\xd4\x37\x3d\x3f\xf5\xd1\x69\xc0\x5f\x01\xbb\xb2\xd6\xef\x23\x38\x2b\x4f\x08\x50\x10\x42\x04\xac\x17\x00\x00'
            ieee = IEEE80211(s)
            self.failUnless(ieee.type == DATA_TYPE)
            self.failUnless(ieee.subtype == D_DATA)
            self.failUnless(ieee.data_frame.dst == '\x00\x02\xb3\xd6\x26\x3c')
            self.failUnless(ieee.data_frame.src == '\x00\x16\x44\xb0\xae\xc6')
            self.failUnless(ieee.data_frame.frag_seq == 0x807e)
            self.failUnless(ieee.data == '\xaa\xaa\x03\x00\x00\x00\x08\x00\x45\x00\x00\x28\x07\x27\x40\x00\x80\x06\x1d\x39\x8d\xd4\x37\x3d\x3f\xf5\xd1\x69\xc0\x5f\x01\xbb\xb2\xd6\xef\x23\x38\x2b\x4f\x08\x50\x10\x42\x04\xac\x17\x00\x00')

            import llc, ip
            llc_pkt = llc.LLC(ieee.data_frame.data)
            ip_pkt = ip.IP(llc_pkt.data)
            self.failUnless(ip_pkt.dst == '\x3f\xf5\xd1\x69')

        def test_80211_data_qos(self):
            s = '\x88\x01\x3a\x01\x00\x26\xcb\x17\x44\xf0\x00\x23\xdf\xc9\xc0\x93\x00\x26\xcb\x17\x44\xf0\x20\x7b\x00\x00\xaa\xaa\x03\x00\x00\x00\x88\x8e\x01\x00\x00\x74\x02\x02\x00\x74\x19\x80\x00\x00\x00\x6a\x16\x03\x01\x00\x65\x01\x00\x00\x61\x03\x01\x4b\x4c\xa7\x7e\x27\x61\x6f\x02\x7b\x3c\x72\x39\xe3\x7b\xd7\x43\x59\x91\x7f\xaa\x22\x47\x51\xb6\x88\x9f\x85\x90\x87\x5a\xd1\x13\x20\xe0\x07\x00\x00\x68\xbd\xa4\x13\xb0\xd5\x82\x7e\xc7\xfb\xe7\xcc\xab\x6e\x5d\x5a\x51\x50\xd4\x45\xc5\xa1\x65\x53\xad\xb5\x88\x5b\x00\x1a\x00\x2f\x00\x05\x00\x04\x00\x35\x00\x0a\x00\x09\x00\x03\x00\x08\x00\x33\x00\x39\x00\x16\x00\x15\x00\x14\x01\x00'
            ieee = IEEE80211(s)
            self.failUnless(ieee.type == DATA_TYPE)
            self.failUnless(ieee.subtype == D_QOS_DATA)
            self.failUnless(ieee.data_frame.dst == '\x00\x26\xcb\x17\x44\xf0')
            self.failUnless(ieee.data_frame.src == '\x00\x23\xdf\xc9\xc0\x93')
            self.failUnless(ieee.data_frame.frag_seq == 0x207b)
            self.failUnless(ieee.data == '\xaa\xaa\x03\x00\x00\x00\x88\x8e\x01\x00\x00\x74\x02\x02\x00\x74\x19\x80\x00\x00\x00\x6a\x16\x03\x01\x00\x65\x01\x00\x00\x61\x03\x01\x4b\x4c\xa7\x7e\x27\x61\x6f\x02\x7b\x3c\x72\x39\xe3\x7b\xd7\x43\x59\x91\x7f\xaa\x22\x47\x51\xb6\x88\x9f\x85\x90\x87\x5a\xd1\x13\x20\xe0\x07\x00\x00\x68\xbd\xa4\x13\xb0\xd5\x82\x7e\xc7\xfb\xe7\xcc\xab\x6e\x5d\x5a\x51\x50\xd4\x45\xc5\xa1\x65\x53\xad\xb5\x88\x5b\x00\x1a\x00\x2f\x00\x05\x00\x04\x00\x35\x00\x0a\x00\x09\x00\x03\x00\x08\x00\x33\x00\x39\x00\x16\x00\x15\x00\x14\x01\x00')
            self.failUnless(ieee.qos_data.control == 0x0)
        
        def test_bug(self):
            s='\x88\x41\x2c\x00\x00\x26\xcb\x17\x44\xf0\x00\x1e\x52\x97\x14\x11\x00\x1f\x6d\xe8\x18\x00\xd0\x07\x00\x00\x6f\x00\x00\x20\x00\x00\x00\x00'
            ieee = IEEE80211(s)
            self.failUnless(ieee.wep == 1)
        
        def test_data_ds(self):
            # verifying the ToDS and FromDS fields and that we're getting the
            # correct values

            s = '\x08\x03\x00\x00\x01\x0b\x85\x00\x00\x00\x00\x26\xcb\x18\x73\x50\x01\x0b\x85\x00\x00\x00\x00\x89\x00\x26\xcb\x18\x73\x50'
            ieee = IEEE80211(s)
            self.failUnless(ieee.type == DATA_TYPE)
            self.failUnless(ieee.to_ds == 1)
            self.failUnless(ieee.from_ds == 1)
            self.failUnless(ieee.data_frame.sa == '\x00\x26\xcb\x18\x73\x50')
            self.failUnless(ieee.data_frame.src == '\x00\x26\xcb\x18\x73\x50')
            self.failUnless(ieee.data_frame.dst == '\x01\x0b\x85\x00\x00\x00')
            self.failUnless(ieee.data_frame.da == '\x01\x0b\x85\x00\x00\x00')

            s = '\x88\x41\x50\x01\x00\x26\xcb\x17\x48\xc1\x00\x24\x2c\xe7\xfe\x8a\xff\xff\xff\xff\xff\xff\x80\xa0\x00\x00\x09\x1a\x00\x20\x00\x00\x00\x00'
            ieee = IEEE80211(s)
            self.failUnless(ieee.type == DATA_TYPE)
            self.failUnless(ieee.to_ds == 1)
            self.failUnless(ieee.from_ds == 0)
            self.failUnless(ieee.data_frame.bssid == '\x00\x26\xcb\x17\x48\xc1')
            self.failUnless(ieee.data_frame.src == '\x00\x24\x2c\xe7\xfe\x8a')
            self.failUnless(ieee.data_frame.dst == '\xff\xff\xff\xff\xff\xff')

            s = '\x08\x02\x02\x01\x00\x02\x44\xac\x27\x70\x00\x1f\x33\x39\x75\x44\x00\x1f\x33\x39\x75\x44\x90\xa4'
            ieee = IEEE80211(s)
            self.failUnless(ieee.type == DATA_TYPE)
            self.failUnless(ieee.to_ds == 0)
            self.failUnless(ieee.from_ds == 1)
            self.failUnless(ieee.data_frame.bssid == '\x00\x1f\x33\x39\x75\x44')
            self.failUnless(ieee.data_frame.src == '\x00\x1f\x33\x39\x75\x44')
            self.failUnless(ieee.data_frame.dst == '\x00\x02\x44\xac\x27\x70')


    unittest.main()
