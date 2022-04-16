package com.github.username.gui;

import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.EventQueue;
import java.awt.FlowLayout;
import java.util.List;
import java.util.Queue;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.SynchronousQueue;

import javax.swing.BoxLayout;
import javax.swing.JButton;
import javax.swing.JComboBox;
import javax.swing.JFileChooser;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JTextField;
import javax.swing.filechooser.FileNameExtensionFilter;

import org.pcap4j.core.BpfProgram.BpfCompileMode;
import org.pcap4j.core.NotOpenException;
import org.pcap4j.core.PcapAddress;
import org.pcap4j.core.PcapDumper;
import org.pcap4j.core.PcapHandle;
import org.pcap4j.core.PcapHandle.TimestampPrecision;
import org.pcap4j.core.PcapNativeException;
import org.pcap4j.core.PcapNetworkInterface;
import org.pcap4j.core.PcapNetworkInterface.PromiscuousMode;
import org.pcap4j.core.PcapStat;
import org.pcap4j.core.Pcaps;
import org.pcap4j.packet.Packet;
import org.pcap4j.util.NifSelector;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.swing.JTextArea;
import java.awt.event.ActionListener;
import java.awt.event.ActionEvent;
import javax.swing.JScrollBar;
import javax.swing.JScrollPane;
import javax.swing.JCheckBox;
import java.awt.event.ItemListener;
import java.io.File;
import java.awt.event.ItemEvent;
import java.awt.GridBagLayout;
import java.awt.GridBagConstraints;
import java.awt.Insets;
import javax.swing.GroupLayout;
import javax.swing.GroupLayout.Alignment;
import javax.swing.JTable;
import javax.swing.table.DefaultTableModel;

import com.github.username.PacketSniffer.PacketSniffer;
import com.github.username.PacketSniffer.UpdateOutput;

import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;

public class Main {
    final static Logger logger = LoggerFactory.getLogger(Main.class);
    private List<PcapNetworkInterface> interfaces;
    private LinkedBlockingQueue<Packet> packetQueue;

    private PacketSniffer packetSniffer;
    private UpdateOutput outputThread;
    private boolean running;
    private DefaultTableModel tableModel;

    private JFrame frame;
    private JTextField txtFilters;
    private JComboBox ddlInterfaces;
    private JTable tblOutput;
    JPanel pnlData;
    JButton start, stop;
    JCheckBox dumpFile;
    JLabel filePath = new JLabel("");
    JTextArea txtData;

    //Launching!
    public static void main(String[] args) {
        EventQueue.invokeLater(new Runnable() {
            public void run() {
                try {
                    Main window = new Main();
                    window.frame.setVisible(true);
                } catch (Exception e) {
                    e.printStackTrace();
                }
            }
        });
    }

    ///Creating application
    public Main() {
        initialize();
        try {
            interfaces = Pcaps.findAllDevs();
            populateInterfaceList();
        } catch( PcapNativeException e) {
            e.printStackTrace();
        }
    }

    //Populating 
    private void populateInterfaceList() {
        for(PcapNetworkInterface face : interfaces) {
            ddlInterfaces.addItem(new Combination(face.getDescription(), face.getName()));
            logger.info("Interface: " + face.getDescription());
        }
    }

    private void StartMonitoring() {
        packetQueue = new LinkedBlockingQueue<>();

        try {
            PcapNetworkInterface interface1 = interfaces.get(ddlInterfaces.getSelectedIndex());
            for(PcapAddress address : interface1.getAddresses()) {
                if(address.getAddress() != null) {
                    logger.info("IP address: " + address.getAddress());
                }
            }

            packetSniffer = new PacketSniffer(packetQueue, interface1, txtFilters.getText());

            if(dumpFile.isSelected()) {
                File file = new File(filePath.getText());
                packetSniffer.setFileOutput(file);
            }
            packetSniffer.start();

            outputThread = new UpdateOutput(packetQueue, tableModel, tblOutput);
            outputThread.start();

            start.setEnabled(false);
            stop.setEnabled(true);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

}
