package com.company;

import javax.swing.*;
import org.jnetpcap.Pcap;
import org.jnetpcap.PcapIf;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public class PacketSniffer {

    // Frame
    private JFrame frame;

    // Lists
    private List<PcapIf> alldevs;

    // Executor
    // Set the thread pool size to 10
    private final ExecutorService exec = Executors.newFixedThreadPool(10);
    public PacketSniffer() {
        alldevs = new ArrayList<>();
        frame = new JFrame("Packet Sniffer");
        frame.setDefaultCloseOperation(WindowConstants.EXIT_ON_CLOSE);
        frame.setSize(600, 400);
        frame.setLayout(new BorderLayout());
        JPanel panel = new JPanel();
        frame.add(panel);
        JLabel label = new JLabel("Select an interface:");
        panel.add(label);
        JComboBox<String> comboBox = new JComboBox<>();
        panel.add(comboBox);
        JButton startButton = new JButton("Sniff");
        startButton.addActionListener(e -> {
            frame.setVisible(false);
            Sniffer sniffer = new Sniffer(alldevs.get(comboBox.getSelectedIndex()));
            sniffer.setVisible(true);
        });
        JButton tab = new JButton("Analysis Mode");
        panel.add(startButton);
        tab.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                Analyser analyser = new Analyser(alldevs.get(comboBox.getSelectedIndex()));
                analyser.setVisible(true);
                frame.setVisible(false);
            }
        });
        panel.add(tab);
        try {
            initDeviceList();
        } catch (IOException ex) {
            ex.printStackTrace();
        }
        // Add the devices to the combo box
        for (PcapIf device : alldevs) {
            comboBox.addItem(device.getDescription());
        }
        // Make the frame visible
        frame.setVisible(true);
    }
    // Method to initialize the list of devices
    public void initDeviceList() throws IOException {
        StringBuilder errbuf = new StringBuilder();

        // Get the list of devices
        int r = Pcap.findAllDevs(alldevs, errbuf);

        if (r == Pcap.NOT_OK || alldevs.isEmpty()) {
            throw new IOException("Can't read list of devices, error is " + errbuf.toString());
        }
    }

    // PacketSnifferThread inner class
    // Main method
    public static void main(String[] args) {
        new PacketSniffer();
    }
}