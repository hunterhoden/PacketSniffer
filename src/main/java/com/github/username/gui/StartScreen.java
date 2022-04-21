package com.github.username.gui;

import javax.swing.JButton;
import javax.swing.JList;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JScrollPane;

import java.awt.Dimension;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.util.ArrayList;
import java.util.List;

import org.pcap4j.core.PcapNativeException;
import org.pcap4j.core.PcapNetworkInterface;
import org.pcap4j.core.Pcaps;

public class StartScreen extends JPanel implements ActionListener {

    private JScrollPane nicList;
    public static String selectedNIC;
    private JList<String> interfaces;
    private JButton confirmBtn;

    public StartScreen() throws PcapNativeException {
        super();
        initComponents();
    }

    private void initComponents() throws PcapNativeException {
        List<String> nicNames = new ArrayList<String>();
        confirmBtn = new JButton("Select Interface");
        for (PcapNetworkInterface nic : Pcaps.findAllDevs()) {
            nicNames.add(nic.getName());
        }
        interfaces = new JList<String>(nicNames.toArray(new String[0]));
        nicList = new JScrollPane(interfaces);
        nicList.setPreferredSize(new Dimension(150, 210));

        confirmBtn.addActionListener(this);

        this.add(nicList);
        this.add(confirmBtn);

    }

    public void actionPerformed(ActionEvent event) {
        Object source = event.getSource();

        if (source.equals(confirmBtn)) {
            selectedNIC = interfaces.getSelectedValue();
            if (selectedNIC == null) {
                JOptionPane.showMessageDialog(this,"Please select an interface");
            } else {
                Main.window.setVisible(false);
                Main.window.getContentPane().removeAll();
                Main.window.setSize(1000,710);
                ScannerViewController controller = new ScannerViewController();
                Main.window.getContentPane().add(controller);
                Main.window.setTitle("Listening on interface "+selectedNIC);
                Main.window.setLocationRelativeTo(null);
                Main.window.setResizable(true);
                Main.window.setVisible(true);
            } 
        }

    }
}
