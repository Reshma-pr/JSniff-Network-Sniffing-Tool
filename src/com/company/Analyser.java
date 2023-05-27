package com.company;

import org.jnetpcap.Pcap;
import org.jnetpcap.PcapIf;
import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.packet.PcapPacketHandler;
import org.jnetpcap.packet.format.FormatUtils;
import org.jnetpcap.protocol.network.Ip4;
import org.jnetpcap.protocol.tcpip.Tcp;
import org.jnetpcap.protocol.tcpip.Udp;

import javax.swing.*;
import javax.swing.table.DefaultTableModel;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
public class Analyser extends javax.swing.JDialog {
    private Pcap pcap;
    private final ExecutorService exec = Executors.newFixedThreadPool(10);
    PcapIf device;
    public Analyser(java.awt.Frame parent, boolean modal) {
        super(parent, modal);
        initComponents();
    }
    public Analyser(PcapIf device){
        this.device=device;
        initComponents();
    }
    // <editor-fold defaultstate="collapsed" desc="Generated Code">
    private void initComponents() {
        jButton1 = new javax.swing.JButton();
        jButton2 = new javax.swing.JButton();
        jButton1.setBackground(Color.green);
        jButton2.setBackground(Color.red);
        jScrollPane1 = new javax.swing.JScrollPane();
        jTable1 = new javax.swing.JTable();
        setDefaultCloseOperation(javax.swing.WindowConstants.DISPOSE_ON_CLOSE);
        jTable1.setBackground(Color.ORANGE);
        jButton1.setText("Start");
        jButton2.setText("Stop");
        DefaultTableModel model = new javax.swing.table.DefaultTableModel(
                new Object[][]{
                },
                new String[]{
                        "No.", "Source Address", "Destination Address", "Protocol", "Length"
                }
        );
        jTable1.setModel(model);
        jButton1.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                jButton1.setEnabled(false);
                StringBuilder errbuf = new StringBuilder();
                int snaplen = 64 * 1024;
                Ip4 ip = new Ip4();
                Tcp tcp = new Tcp();
                Udp udp = new Udp();
                Thread thread = new Thread(new Runnable() {
                    @Override
                    public void run() {
                        pcap = Pcap.openLive(device.getName(), snaplen, 1000, Pcap.MODE_PROMISCUOUS, errbuf);
                        PcapPacketHandler<String> packetHandler = new PcapPacketHandler<String>() {
                            @Override
                            public void nextPacket(PcapPacket packet, String s) {
                                String src, dest;
                                int len;
                                long num = packet.getFrameNumber();
                                if (packet.hasHeader(ip)) {
                                    src = FormatUtils.ip(ip.source());
                                    dest = FormatUtils.ip(ip.source());
                                    len = ip.length();
                                    model.addRow(new Object[]{num, src, dest, "IP", len});
                                    int index = model.getRowCount() - 1;
                                }  if (packet.hasHeader(tcp)) {
                                    src = String.valueOf(tcp.source());
                                    dest = String.valueOf(tcp.destination());
                                    len = tcp.getLength();
                                    model.addRow(new Object[]{num, src, dest, "TCP", len,});
                                }  if (packet.hasHeader(udp)) {
                                    src = String.valueOf(udp.source());
                                    dest = String.valueOf(udp.destination());
                                    len = udp.getLength();
                                    model.addRow(new Object[]{num, src, dest, "UDP", len});
                                }
                            }
                        };
                        pcap.loop(-1, packetHandler, "");
                    }
                });
                exec.execute(thread);
            }
        });
        jButton2.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                if (pcap != null) {
                    pcap.close();
                    exec.shutdownNow();
                    System.exit(0);
                }
                jButton2.setEnabled(false);
                jButton1.setEnabled(true);
            }
        });
        jScrollPane1.setViewportView(jTable1);

        javax.swing.GroupLayout layout = new javax.swing.GroupLayout(getContentPane());
        getContentPane().setLayout(layout);
        layout.setHorizontalGroup(
                layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                        .addGroup(layout.createSequentialGroup()
                                .addContainerGap()
                                .addComponent(jButton1, javax.swing.GroupLayout.PREFERRED_SIZE, 250, javax.swing.GroupLayout.PREFERRED_SIZE)
                                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                                .addComponent(jButton2, javax.swing.GroupLayout.DEFAULT_SIZE, 250, Short.MAX_VALUE)
                                .addContainerGap())
                        .addComponent(jScrollPane1, javax.swing.GroupLayout.Alignment.TRAILING, javax.swing.GroupLayout.PREFERRED_SIZE, 0, Short.MAX_VALUE)
        );
        layout.setVerticalGroup(
                layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                        .addGroup(layout.createSequentialGroup()
                                .addContainerGap()
                                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                                        .addComponent(jButton2)
                                        .addComponent(jButton1))
                                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                                .addComponent(jScrollPane1, javax.swing.GroupLayout.DEFAULT_SIZE, 300, Short.MAX_VALUE)
                                .addContainerGap())
        );

        pack();
    }
    public static void main(String args[]) {
        try {
            for (javax.swing.UIManager.LookAndFeelInfo info : javax.swing.UIManager.getInstalledLookAndFeels()) {
                if ("Nimbus".equals(info.getName())) {
                    javax.swing.UIManager.setLookAndFeel(info.getClassName());
                    break;
                }
            }
        } catch (ClassNotFoundException | IllegalAccessException | InstantiationException | UnsupportedLookAndFeelException ex) {
            java.util.logging.Logger.getLogger(Analyser.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
        }
        //</editor-fold>
        /* Create and display the dialog */
        java.awt.EventQueue.invokeLater(new Runnable() {
            public void run() {
                Analyser dialog = new Analyser(new javax.swing.JFrame(), true);
                dialog.addWindowListener(new java.awt.event.WindowAdapter() {
                    @Override
                    public void windowClosing(java.awt.event.WindowEvent e) {
                        System.exit(0);
                    }
                });
                dialog.setVisible(true);
            }
        });
    }
    // Variables declaration - do not modify
    private javax.swing.JButton jButton1;
    private javax.swing.JButton jButton2;
    private javax.swing.JScrollPane jScrollPane1;
    private javax.swing.JTable jTable1;
    // End of variables declaration
}
