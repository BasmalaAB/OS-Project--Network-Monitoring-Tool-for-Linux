extern crate pcap;
use pcap::Device;

fn capture_packets()
{
     let mut cap = Device::lookup().unwrap().unwrap().open().unwrap();
   
    while let Ok(packet) = cap.next_packet() {
                println!("recieved packet! {:?}", packet);
            }
}

fn main() {
    // Open the pcap capture device
   capture_packets();
}