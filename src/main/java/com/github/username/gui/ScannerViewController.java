package com.github.username.gui;

import java.awt.BorderLayout;

import javax.swing.JOptionPane;
import javax.swing.JPanel;

import org.pcap4j.core.PcapNativeException;

public class ScannerViewController extends JPanel {

    private ScannerTopPanel top;
    static ScannerCaptureView captureView;

    public ScannerViewController() {
        super();
        initComponents();
    }

    private void initComponents() {
        this.setLayout(new BorderLayout());
        top = new ScannerTopPanel();
        try {
            captureView = new ScannerCaptureView();
        } catch (PcapNativeException e) {
            JOptionPane.showMessageDialog(this,"Fatal - PcapNativeException");
            e.printStackTrace();
        }
        this.add(top, BorderLayout.NORTH);
        this.add(captureView, BorderLayout.CENTER);
    }
}