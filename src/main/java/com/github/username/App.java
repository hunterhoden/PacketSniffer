//App.java
package com.github.username;

import java.io.IOException;

import org.pcap4j.core.NotOpenException;
import org.pcap4j.core.PacketListener;
import org.pcap4j.core.Pcaps;
import org.pcap4j.core.PcapHandle;
import org.pcap4j.core.PcapNativeException;
import org.pcap4j.core.PcapNetworkInterface;
import org.pcap4j.core.PcapNetworkInterface.PromiscuousMode;
import org.pcap4j.packet.Packet;
//import org.pcap4j.util.NifSelector; might not need
import java.util.List;
import java.util.Scanner;


public class App {

    static PcapNetworkInterface getNetworkDevice() throws IOException {
        //Network device for storing all devices
        List<PcapNetworkInterface> devices = null;
        PcapNetworkInterface listeningDevice = null;
        //Listing network interfaces from the terminal this could be changed to jFrame 
        try {
            devices = Pcaps.findAllDevs();
        } catch (PcapNativeException e) {
            throw new IOException(e.getMessage());
        }
        //if there are no devices to listen for
        if(devices == null || devices.isEmpty()) {
            throw new IOException("Nothing to listen for");
        }
        //Checking what device to listen for
        else {
            try (Scanner scnr = new Scanner(System.in)) {
                System.out.print("Choose what to listen for: \n");
                for(PcapNetworkInterface i : devices) {
                    //Listing options of what to listen for. Not sure if you could dynamically assign buttons 
                    //but if you could it might be nice to put here.
                    System.out.print( i + "\n");
                }
                System.out.println("");
                String input = scnr.nextLine();
                for(PcapNetworkInterface j : devices) {
                    if(String.valueOf(j) == input) {
                        scnr.close(); //clean up
                        listeningDevice = j;
                        return listeningDevice;
                    } 
                }
                scnr.close(); //clean up
            }
        }
        
        return null;
    }

    public static void main( String[] args ) throws IOException, PcapNativeException, NotOpenException {
        PcapNetworkInterface device = getNetworkDevice();
        //Opening the device in...
        int snapShotLength = 65536; // Bytes
        int readTimeout = 50; //Milliseconds
        final PcapHandle handle;
        handle = device.openLive(snapShotLength, PromiscuousMode.PROMISCUOUS, readTimeout);
        //Listener that defines what we are doing with packets
        PacketListener listen = new PacketListener() {
            @Override 
            public void gotPacket(Packet packet) {
                System.out.println(handle.getTimestamp());
                System.out.println(packet);
            }
        };
        //Handler loop using listener
        try {
            int maxPackets = 50;
            handle.loop(maxPackets, listen);
        }  catch (InterruptedException e) {
            e.printStackTrace();
        }

        handle.close(); //clean up
    }
}
