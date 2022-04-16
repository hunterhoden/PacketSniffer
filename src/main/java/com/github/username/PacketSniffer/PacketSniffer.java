package com.github.username.PacketSniffer;

import com.sun.jna.Platform;

import java.io.File;

import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.atomic.AtomicBoolean;

import org.pcap4j.core.BpfProgram.BpfCompileMode;
import org.pcap4j.core.PcapDumper;
import org.pcap4j.core.PcapHandle;
import org.pcap4j.core.PcapNetworkInterface;
import org.pcap4j.core.PcapNetworkInterface.PromiscuousMode;
import org.pcap4j.core.PcapStat;
import org.pcap4j.packet.Packet;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


public class PacketSniffer extends Thread {

    final static Logger logger = LoggerFactory.getLogger(PacketSniffer.class);
    LinkedBlockingQueue<Packet> packetQueue; // Threat safe queue to put packets in
    PcapNetworkInterface networkInterface; // Pulling packets from here
    volatile AtomicBoolean running = new AtomicBoolean(); //Running boolean 
    boolean gotoOutput = false; //Should we write to the output file?
    File file = null; // THE FILE
    String filter; //Being good and filtering

    public PacketSniffer(LinkedBlockingQueue<Packet> packetQueue, PcapNetworkInterface networkInterface, String filter) {
        this.packetQueue = packetQueue;
        this.networkInterface = networkInterface;
        this.filter = filter;
        running.set(true);
    }

    //Creating output file
    public void setFileOutput(File file) {
        this.file = file;
        gotoOutput = true;
    }
    //Stop updating atomicbool
    public void StopUpdate() { running.set(false); }

    @Override
    public void run() {
        PcapDumper dumper = null; //DUMPING 

        try {
            //Setting to max size of ethernet packet and in promiscuous mode with .5 second timeout
            final PcapHandle handle = networkInterface.openLive(65536, PromiscuousMode.PROMISCUOUS, 500);
            handle.setFilter(filter, BpfCompileMode.OPTIMIZE);
            //if we are writing to output file
            if(gotoOutput) dumper = handle.dumpOpen(file.getAbsolutePath());
            
            int num = 0;
            while(running.get()) {
                Packet packet = handle.getNextPacket();
                if(packet == null) continue;
                else {
                    packetQueue.add(packet);
                    if(gotoOutput) dumper.dump(packet, handle.getTimestamp());
                    logger.debug(handle.getTimestamp().toString());
                    logger.debug(packet.toString());
                    num++;
                    if(num >= 5000) break;
                }
            }

            PcapStat stats = handle.getStats();
            logger.info("ps_recv: " + stats.getNumPacketsReceived());
            logger.info("ps_drop: " + stats.getNumPacketsDropped());
            logger.info("ps_ifdrop: " + stats.getNumPacketsDroppedByIf());
            if(Platform.isWindows()) logger.info("bs_capt: " + stats.getNumPacketsCaptured());
            if(gotoOutput) dumper.close();
            handle.close();
        } catch ( Exception e) {
            e.printStackTrace();
        }
    }
}
