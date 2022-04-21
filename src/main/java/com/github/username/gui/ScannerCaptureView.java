package com.github.username.gui;

import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTable;
import javax.swing.SwingConstants;
import javax.swing.table.DefaultTableCellRenderer;
import javax.swing.table.DefaultTableModel;

import java.awt.GridLayout;
import org.pcap4j.core.PcapNativeException;

public class ScannerCaptureView extends JPanel {
    static String[] columnNames = { "<html><h3>Source <h3></html>","<html><h3>Src Port/Service<h3></html>", 
    "<html><h3>Destination<h3></html>","<html><h3>Dst Port/Service<h3></html>","<html><h3>Protocol<h3></html>", 
    "<html><h3>No.<h3></html>", "<html><h3>Info<h3></html>" };
    static DefaultTableModel tableModel = new DefaultTableModel(columnNames, 0) {
        public boolean isCellEditable(int row, int column) {
            return false;
        }
    };

    DefaultTableCellRenderer centerRenderer = new DefaultTableCellRenderer();

    static JTable captureTable;

    public ScannerCaptureView() throws PcapNativeException {
        super(new GridLayout());
        initComponents();
    }

    private void initComponents() throws PcapNativeException {
        captureTable = new JTable(tableModel);
        DefaultTableCellRenderer headerRenderer = (DefaultTableCellRenderer)captureTable.getTableHeader().getDefaultRenderer();
        centerRenderer.setHorizontalAlignment(SwingConstants.CENTER);
        headerRenderer.setHorizontalAlignment(SwingConstants.CENTER);
        captureTable.setDefaultRenderer(Object.class,centerRenderer);
        captureTable.getTableHeader().setDefaultRenderer(headerRenderer);
        this.add(new JScrollPane(captureTable));
    }
}