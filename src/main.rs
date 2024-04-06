extern crate pcap;
use pcap::Device;
use pnet::packet::tcp::TcpPacket;
use pnet::packet::ethernet::{EthernetPacket, EtherTypes};
use pnet::packet::Packet;
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::ipv6::Ipv6Packet;

fn main() {
    // Open the pcap capture device
   capture_packets();
}

fn extract_tcp_socket(packet: &[u8]) -> Option<(u16,u16,u16)>{
	if let Some(tcp) = TcpPacket::new(packet) {
		let src_port = tcp.get_source();
		let dst_port = tcp.get_destination();
		let checksum = tcp.get_checksum(); 
		//gets IP address of sender
		//get IP Address of receiver
	
		Some((src_port,dst_port,checksum))
	}
	else {
	None
	}
}


fn extract_ip_addresses(packet: &[u8]) {
	
	
	if let Some(ethernet_packet) = EthernetPacket::new(packet) {
	    match ethernet_packet.get_ethertype(){
		EtherTypes::Ipv6 => {
			if let Some(ipv6_packet) = Ipv6Packet::new(ethernet_packet.payload()){
				println!("IPv6 Packet- Source: {}, Destination: {}",
				 ipv6_packet.get_source(),
				 ipv6_packet.get_destination());	
			}
		}
		EtherTypes::Ipv4 => {
			if let Some(ipv4_packet) = Ipv4Packet::new(ethernet_packet.payload()){
				println!("IPv4 Packet- Source: {}, Destination: {}",
				 ipv4_packet.get_source(), 
				 ipv4_packet.get_destination());	
			}
		}
		_ => {
			println!("Unknown EtherType {:?}", ethernet_packet.get_ethertype());
		}
	    }
	}
}



fn capture_packets()
{
     let mut cap = Device::lookup().unwrap().unwrap().open().unwrap();
    
    while let Ok(packet) = cap.next_packet() {
                match extract_tcp_socket(&packet){
                	Some((src_port, dst_port, checksum)) => {
                		println!("Source Port: {}, Destination Port: {}, Checksum: {}", src_port, dst_port, checksum);
                	},
                	None => println!("TCP Socket not found in the packet header"),
                }
                
                extract_ip_addresses(&packet);
                
            }
}


