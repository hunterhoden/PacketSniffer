package com.github.username.gui;

import javax.swing.ImageIcon;
import javax.swing.JButton;
import javax.swing.JPanel;

import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.Color;



public class ScannerTopPanel extends JPanel implements ActionListener {

    ImageIcon startIcon = new ImageIcon("resources/start.png");
    ImageIcon stopIcon = new ImageIcon("resources/stop.png");
    ImageIcon backIcon = new ImageIcon("resources/back.png");
    ImageIcon clearIcon = new ImageIcon("resources/trash.jpg");

    JButton toggleCaptureBtn = new JButton(startIcon);
    JButton returnBtn = new JButton(backIcon);
    JButton clearBtn = new JButton(clearIcon);

    public ScannerTopPanel() {
        super();
        initComponents();
    }

    private void initComponents() {
        this.setBackground(Color.WHITE);
        toggleCaptureBtn.setOpaque(false);
        toggleCaptureBtn.setContentAreaFilled(false);
        toggleCaptureBtn.setBorderPainted(false);
        toggleCaptureBtn.setFocusPainted(false);

        returnBtn.setOpaque(false);
        returnBtn.setContentAreaFilled(false);
        returnBtn.setBorderPainted(false);
        returnBtn.setFocusPainted(false);

        clearBtn.setOpaque(false);
        clearBtn.setContentAreaFilled(false);
        clearBtn.setBorderPainted(false);
        clearBtn.setFocusPainted(false);

        toggleCaptureBtn.addActionListener(this);
        returnBtn.addActionListener(this);
        clearBtn.addActionListener(this);

        this.add(returnBtn);
        this.add(toggleCaptureBtn);
        this.add(clearBtn);
    }

    public void refreshButtons() {
        if (PacketSniffer.capturing) {
            toggleCaptureBtn.setIcon(stopIcon);
        } else {
            toggleCaptureBtn.setIcon(startIcon);
        }
    }

    public void actionPerformed(ActionEvent event) {
        PacketSniffer sniffer = new PacketSniffer();
        Thread sniffThread = new Thread(sniffer);
        Object source = event.getSource();
        if (source.equals(toggleCaptureBtn)) {
            if (PacketSniffer.capturing) {
                PacketSniffer.capturing = false;
                
            } else {
                PacketSniffer.capturing = true;
                sniffThread.start();
            }
            refreshButtons();
            this.revalidate();
            this.repaint();
        }
        else if (source.equals(returnBtn)) {
            Main.window.dispose();
            ScannerCaptureView.tableModel.setRowCount(0);
            new MainWindow();
        }
        else if (source.equals(clearBtn)) {
            ScannerCaptureView.tableModel.setRowCount(0);
            PacketSniffer.packetNum = 1;
        }
    }
    
}
