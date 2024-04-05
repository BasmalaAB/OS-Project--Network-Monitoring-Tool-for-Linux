extern crate pcap;
use pcap::Device;

fn main() {
    // Open the pcap capture device
    let mut cap = Device::lookup().unwrap().unwrap().open().unwrap();
    
    while let Ok(packet) = cap.next_packet() {
                println!("recieved packet! {:?}", packet);
            }
        
}
