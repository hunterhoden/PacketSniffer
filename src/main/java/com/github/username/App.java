//App.java
package com.github.username;

import java.io.IOException;

import org.pcap4j.core.NotOpenException;
import org.pcap4j.core.PacketListener;
import org.pcap4j.core.PcapHandle;
import org.pcap4j.core.PcapNativeException;
import org.pcap4j.core.PcapNetworkInterface;
import org.pcap4j.core.PcapNetworkInterface.PromiscuousMode;
import org.pcap4j.packet.Packet;
import org.pcap4j.util.NifSelector;
import java.util.ArrayList;
import java.util.Scanner;


public class App {

    static PcapNetworkInterface getNetworkDevice() {
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
        if(devices == null || deviecs.isEmpty()) {
            throw new IOException("Nothing to listen for");
        }
        //Checking what device to listen for
        else {
            Scanner scnr = new Scanner(System.in);
            System.out.print("Choose what to listen for: ");
            for(PcapNetworkInterface i : devices) {
                System.out.print(devices[i] + ", ");
            }
            System.out.println("");
            String input = scnr.nextLine();
            for(PcapNetworkInterface j : devices) {
                if(String.valueOf(devices[j]) == input) {
                    listeningDevice = devices[j];
                    return listeningDevice;
                } 
            }
        }
        
        return null;
    }

    public static void main( String[] args ) {
        PcapNetworkInterface device = getNetworkDevice();

        //Opening the device in...
        int snapShotLength = 65536; // Bytes
        int readTimeout = 50; //Milliseconds
       // final PcapHandle handle;
        // handle = devices.openLive
    }
}