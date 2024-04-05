extern crate pcap;
use pcap::Device;
use pnet::packet::tcp::TcpPacket;


fn extract_tcp_socket(packet: &[u8]) -> Option<(u16,u16)>{
	if let Some(tcp) = TcpPacket::new(packet) {
		let src_port = tcp.get_source();
		let dst_port = tcp.get_destination();
		//let src_IP = tcp.get_ //gets IP address of sender
		//get IP Address of receiver
		Some((src_port,dst_port))
	}
	else {
	None
	}
}


fn capture_packets()
{

     let mut cap = Device::lookup().unwrap().unwrap().open().unwrap();
    
    while let Ok(packet) = cap.next_packet() {
                match extract_tcp_socket(&packet){
                	Some((src_port, dst_port)) => {
                		println!("Source Port: {}, Destination Port: {}", src_port, dst_port);
                	},
                	None => println!("TCP Socket not found in the packet header"),
                }
            }

}

fn main() {
    // Open the pcap capture device
   capture_packets();
}
