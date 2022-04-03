package com.github.username;

import java.io.IOException;
import org.jpcap4.core.PcapNetworkInterface;
import org.jpcap4.util.NifSelector;


public class App {

    public static void main( String[] args ) {
     
        //Network capturing device
        PcapNetworkInterface device = null;

        //try listening 
        try {
            device = new NifSelector().selectNetworkInterface;
        } catch (IOException e) { e.printStackTrace(); }
        
        //Display Which output the user chooses
        System.out.println("Choose what to listen to: " + device); 

    }
}
