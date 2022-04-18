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
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.awt.event.MouseEvent;
import java.awt.event.MouseListener;

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

    private void initialize() {
        frame = new JFrame();
        frame.setBounds(100, 100, 708, 496);
        frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        frame.getContentPane().setLayout(new BorderLayout(0,0));

        JPanel panelSide = new JPanel();
        JPanel paneOne = new JPanel();
        panelSide.setLayout(new BoxLayout(panelSide, BoxLayout.Y_AXIS));
        panelSide.add(paneOne);
        paneOne.setLayout(new BoxLayout(paneOne, BoxLayout.X_AXIS));

        start = new JButton("\u25A0");
        start.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent arg0) { 
                StartMonitoring(); 
            }
        });

        paneOne.add(start);
        start.setForeground(new Color(0, 255, 0));

        stop = new JButton("\u25A0");
        stop.addActionListener( new ActionListener() {
            public void actionPerformed(ActionEvent arg0) {
                packetSniffer.stopUpdate();
                outputThread.stopUpdate();
                start.setEnabled(true);
                stop.setEnabled(false);
            }
        });
        stop.setEnabled(false);

        paneOne.add(stop);
        stop.setForeground(new Color(255, 0, 0));

        JPanel paneTwo = new JPanel();
        panelSide.add(paneTwo);
        paneTwo.setLayout(new FlowLayout(FlowLayout.LEADING, 5, 5));

        JLabel labelInterface = new JLabel("Interface");
        paneTwo.add(labelInterface);

        ddlInterfaces = new JComboBox();
        paneTwo.add(ddlInterfaces);

        JPanel paneThree = new JPanel();
        panelSide.add(paneThree);

        JLabel labelArguments = new JLabel("Filter");
        paneThree.add(labelArguments);

        txtFilters = new JTextField();
        paneThree.add(txtFilters);
        txtFilters.setColumns(10);

        JPanel paneFour = new JPanel();
        panelSide.add(paneFour);

        //DUMP FILE
        dumpFile = new JCheckBox("Enabled");
        dumpFile.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent arg0) {
                if(dumpFile.isSelected()) {
                    JFileChooser chooser = new JFileChooser();
                    FileNameExtensionFilter filter = new FileNameExtensionFilter("pcap file", ".pcapFile");
                    chooser.setFileFilter(filter);
                    int rtnValue = chooser.showSaveDialog(frame);
                    if(rtnValue == JFileChooser.APPROVE_OPTION) {
                        filePath.setText(chooser.getSelectedFile().getAbsolutePath());
                        if(!filePath.getText().endsWith(".pcap")) {
                            filePath.setText(filePath.getText() + ".pcap");
                        }
                    }
                    else if(rtnValue == JFileChooser.CANCEL_OPTION) {
                        dumpFile.setSelected(false);
                        filePath.setText("");
                    }
                }
                else {
                    dumpFile.setSelected(false);
                    filePath.setText("");
                };
            }
        });

        paneFour.setLayout(new FlowLayout(FlowLayout.CENTER, 5, 5));
        JLabel labelDump = new JLabel("Dump File");
        paneFour.add(labelDump);
        paneFour.add(dumpFile);
        frame.getContentPane().add(panelSide, BorderLayout.WEST);

        JPanel panel = new JPanel();
        panelSide.add(panel);

        JPanel panelCenter = new JPanel();
        frame.getContentPane().add(panelCenter, BorderLayout.CENTER);
        panelCenter.setLayout(new BorderLayout(2,2));

        tableModel = new DefaultTableModel(new Object[][]{}, new String[] {"Type", "Src", "Dst","Data"});

        tblOutput = new JTable();
        tblOutput.addMouseListener(new MouseAdapter() {
            @Override
            public void mouseClicked(MouseEvent arg0) {
                int row = tblOutput.rowAtPoint(arg0.getPoint());
                int col = tblOutput.columnAtPoint(arg0.getPoint());
                if(row >= 0 && col >= 0) {
                    String data = tableModel.getValueAt(tblOutput.getSelectedRow(), 3).toString();
                    txtData.setText(data);
                    pnlData.setVisible(true);
                }
            }
        });
        tblOutput.setModel(tableModel);
        tblOutput.setShowHorizontalLines(false);
        JScrollPane scrollPane = new JScrollPane(tblOutput);
        panelCenter.add(scrollPane, BorderLayout.CENTER);

        pnlData = new JPanel();
        panelCenter.add(pnlData, BorderLayout.SOUTH);
        pnlData.setLayout(new BorderLayout(0,0));

        txtData = new JTextArea();
        pnlData.add(txtData, BorderLayout.CENTER);

        JButton closeData = new JButton("Close");
        closeData.addMouseListener(new MouseAdapter() {
            @Override
            public void mousePressed(MouseEvent arg0) {
                pnlData.setVisible(false);
            }
        });
        pnlData.add(closeData, BorderLayout.EAST);
        pnlData.setVisible(false);
        frame.getContentPane().add(filePath, BorderLayout.SOUTH);
    }

}
