package com.github.username;

import java.io.IOException;

import com.sun.jna.Platform;

import org.pcap4j.core.NotOpenException;
import org.pcap4j.core.PacketListener;
import org.pcap4j.core.PcapDumper;
import org.pcap4j.core.PcapHandle;
import org.pcap4j.core.PcapNativeException;
import org.pcap4j.core.PcapNetworkInterface;
import org.pcap4j.core.PcapStat;
import org.pcap4j.core.BpfProgram.BpfCompileMode;
import org.pcap4j.core.PcapNetworkInterface.PromiscuousMode;
import org.pcap4j.packet.Packet;
import org.pcap4j.util.NifSelector;


public class App {

    static PcapNetworkInterface getNetworkDevice() throws IOException {
        //Network device for storing all devices
        PcapNetworkInterface devices = null;

        //Listing network interfaces from the terminal this could be changed to jFrame 
        try {
            devices = new NifSelector().selectNetworkInterface();
        } catch (IOException e) {
            e.printStackTrace();
        }
        //if there are no devices to listen for
        if(devices == null) {
            throw new IOException("No device selected");
        }
        
        return devices;
    }

    public static void main( String[] args ) throws IOException, PcapNativeException, NotOpenException {
        //Setting up devices and presenting options in terminal
        PcapNetworkInterface device = getNetworkDevice();
        //System.out.println("Choose a device: " + device);

        //Opening the device in...
        int snapShotLength = 65536; // Bytes
        int readTimeout = 200; //Milliseconds
        final PcapHandle handle; 
        handle = device.openLive(snapShotLength, PromiscuousMode.PROMISCUOUS, readTimeout); //Handler set up
        PcapDumper dumper = handle.dumpOpen("output.pcap"); //Output file for packet info

        //Only listening for tcp packets (HTTP) 
        handle.setFilter("tcp port 80", BpfCompileMode.OPTIMIZE);

        //Listener that defines what we are doing with packets
        PacketListener listen = new PacketListener() {
            @Override 
            public void gotPacket(Packet packet) {
                System.out.println(handle.getTimestamp());
                System.out.println(packet);
                //Dumping packets to file
                try {
                    dumper.dump(packet, handle.getTimestamp());
                } catch (NotOpenException e) {
                    e.printStackTrace();
                }
            }
        };
        //Handler loop using listener
        try {
            int maxPackets = 50;
            handle.loop(maxPackets, listen);
        }  catch (InterruptedException e) {
            e.printStackTrace();
        }

        //Printing handler stats
        PcapStat stats = handle.getStats(); 
        System.out.println("Packets received: " + stats.getNumPacketsReceived());
        System.out.println("Packets dropped: " + stats.getNumPacketsDropped());
        System.out.println("Packets dropped by interface: " + stats.getNumPacketsDroppedByIf());

        //Windows only WinPcap
        if(Platform.isWindows()) System.out.println("Packets Captured: " + stats.getNumPacketsCaptured()); 

        handle.close(); //clean up
        dumper.close(); //clean up
    }
}
