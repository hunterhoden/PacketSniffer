package com.github.username.gui;

import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.atomic.AtomicBoolean;

import javax.swing.JTable;
import javax.swing.table.DefaultTableModel;

import org.pcap4j.packet.ArpPacket;
import org.pcap4j.packet.DnsPacket;
import org.pcap4j.packet.IcmpV4CommonPacket;
import org.pcap4j.packet.IpV4Packet;
import org.pcap4j.packet.IpV6Packet;
import org.pcap4j.packet.Packet;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class UpdateOutput extends Thread {
    
    final static Logger logger = LoggerFactory.getLogger(UpdateOutput.class);

    volatile AtomicBoolean running = new AtomicBoolean(); //ATOMICBOOLEAN == AUTOMATICALLY CHANGING BOOLEAN
    DefaultTableModel tableModel;
    LinkedBlockingQueue<Packet> packetQueue; //Packets waiting 
    JTable table;

    public UpdateOutput(LinkedBlockingQueue<Packet> packetQueue, DefaultTableModel tableModel, JTable table) {
        this.tableModel = tableModel;
        this.table = table;
        this.packetQueue = packetQueue;
        running.set(true); //As long as true continue
    }

    public void stopUpdate() { //STOP UPDATING
        running.set(false);
    }

    @Override 
    public void run() {

        boolean changed = false;

        //While its running and the queue isn't empty
        while(running.get() || !packetQueue.isEmpty()) {
            try {
                changed = false;
                while(!packetQueue.isEmpty()) {
                    //Setting limit to remove top row
                    if(tableModel.getRowCount() > 1000) tableModel.removeRow(0);
                    //STATIC PACKET FACTORY REQUIRED
                    Packet packet = packetQueue.poll();
                    //IPv4
                    if(packet.contains(IpV4Packet.class)) { 
                        IpV4Packet ip4v = packet.get(IpV4Packet.class); 
                        //looking through the packet if its ipv4
                        if(ip4v.getPayload().contains(DnsPacket.class)) {
                            DnsPacket dns = ip4v.getPayload().get(DnsPacket.class);
                            //formatting output
                            tableModel.addRow(new Object[] { "DNS", ip4v.getHeader().getSrcAddr(),
                                               ip4v.getHeader().getDstAddr(), dns.toString() });
                        }
                    }
                    //IPv6
                    else if(packet.contains(IpV6Packet.class)) { 
                        IpV6Packet ip6v = packet.get(IpV6Packet.class);

                        if(ip6v.getPayload().contains(DnsPacket.class)) {
                            DnsPacket dns = ip6v.getPayload().get(DnsPacket.class); 
                            tableModel.addRow(new Object[] { "DNS", ip6v.getHeader().getSrcAddr(),
                                               ip6v.getHeader().getDstAddr(), dns.toString() });
                        }
                        else if(ip6v.getPayload().contains(IcmpV4CommonPacket.class)) {
                            IcmpV4CommonPacket icmp = ip6v.getPayload().get(IcmpV4CommonPacket.class);
                            tableModel.addRow(new Object[] { "ICMP", ip6v.getHeader().getSrcAddr(),
                                                ip6v.getHeader().getDstAddr(), icmp.toString() });
                        }
                        else {
                            tableModel.addRow(new Object[] { "IPv6", ip6v.getHeader().getSrcAddr(),
                                                ip6v.getHeader().getDstAddr(), ip6v.toString() });
                        }
                    }
                    //ARP (2 layer packet)
                    else if(packet.contains(ArpPacket.class)) {
                        ArpPacket arp = packet.get(ArpPacket.class);
                        tableModel.addRow(new Object[] {"ARP", arp.getHeader().getSrcHardwareAddr(),
                                                arp.getHeader().getDstHardwareAddr(), arp.toString() });
                    }
                    else {
                        logger.info("Unkown packet type");
                    }
                    changed = true;
                }
                if(changed) table.getParent().revalidate(); //update the output table GUI

                try {
                    Thread.sleep(250);
                } catch (Exception e) { e.printStackTrace(); }
            } catch (Exception e) { 
                e.printStackTrace(); 
            }
        }
    }
}
