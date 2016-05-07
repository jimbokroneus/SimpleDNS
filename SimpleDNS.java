package edu.wisc.cs.sdn.simpledns;

import edu.wisc.cs.sdn.simpledns.packet.DNS;
import edu.wisc.cs.sdn.simpledns.packet.DNSQuestion;
import edu.wisc.cs.sdn.simpledns.packet.DNSRdataAddress;
import edu.wisc.cs.sdn.simpledns.packet.DNSResourceRecord;


import java.io.BufferedReader;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.net.*;
import java.nio.ByteBuffer;
import java.util.List;

public class SimpleDNS
{
    private final static int MAX_PACKET_SIZE = 1500;
    private final static int DNS_PORT = 53;
    private final static int LOCAL_DNS_PORT = 8053;

    private static String rootIp;
    private static String ec2;
    private static DatagramSocket serverSocket;

    public static void main(String[] args)
    {
	//conventions
        System.out.println("Hello, DNS!");
        boolean run = true;

        if (args.length != 4){
            System.out.println("Usage: -r <root server ip> -e <ec2 csv>");
            System.exit(-1);
        }

        rootIp = args[1];
        ec2 = args[3];

        try {
            //establish socket connection
            serverSocket = new DatagramSocket(LOCAL_DNS_PORT);

            while(run) {




                //get datagram packet
                byte[] buff = new byte[MAX_PACKET_SIZE];
                DatagramPacket packet = new DatagramPacket(buff, buff.length);
                serverSocket.receive(packet);

                //deserialize into dns packet
                DNS dnsPacket = DNS.deserialize(buff, buff.length);

                if(dnsPacket.getOpcode() == 0 && dnsPacket.isQuery()){

                    //get the first question (we don't have to implement for multiple)
                    DNSQuestion question = dnsPacket.getQuestions().get(0);

                    int type = question.getType();

                    if(type == DNS.TYPE_A || type == DNS.TYPE_AAAA || type == DNS.TYPE_CNAME || type == DNS.TYPE_NS) {
                        //TODO: double check
                        handlePacketRecursively(dnsPacket, packet);
                    }
                    else{
                        System.out.println("Not a A, AAAA, CNAME, or NS query");
                    }

                }


            }

        } catch (IOException e) {
            e.printStackTrace();
        }
        serverSocket.close();
    }

    /**
     * Handles Packets in a recursive manner.
     * It handles single question cases.
     *
     *
     * @param dnsPacket the dns packet
     * @param returnToSender the packet to be returned to the sender
     * @throws IOException (caught in main)
     */
    private static void handlePacketRecursively(DNS dnsPacket, DatagramPacket returnToSender) throws IOException{

        InetAddress inet = InetAddress.getByName(rootIp);
        DatagramSocket socket = new DatagramSocket();
        //socket.connect(inet, DNS_PORT);
        byte buff[] = new byte[MAX_PACKET_SIZE];
        DNS dnsPacketToSendToHost = dnsPacket;

        boolean run = true;
        int ttl = 100;

        System.out.println(inet);
        //System.out.println(socket.getRemoteSocketAddress().toString());

        while(run && ttl>0) {
            System.out.println("Start loop***************************************************************");
            DatagramPacket nQuery = new DatagramPacket(dnsPacket.serialize(), 0, dnsPacket.getLength(), inet, DNS_PORT);
            socket.send(nQuery);

            System.out.println("Sending packet:");
            System.out.println(dnsPacket.toString());

            System.out.println("Recieve packet:");
            socket.receive(new DatagramPacket(buff, buff.length));
            dnsPacket = DNS.deserialize(buff, buff.length);

            System.out.println(dnsPacket.toString());

            if (!dnsPacket.isRecursionDesired()) {
                System.out.println("No recursion desired");
                //send to client
                sendToClient(dnsPacketToSendToHost, returnToSender);
                run = false;

            } else {

                System.out.println("Recursion");
                dnsPacket.setQuery(true);
                //select next server to send request to
                for (DNSResourceRecord record : dnsPacket.getAdditional()) {

                    //only handle IPv4
                    if (record.getType() == DNS.TYPE_A) {

                        DNSRdataAddress address = (DNSRdataAddress) record.getData();
                        System.out.println("DNS Address: " + address);
                        inet = InetAddress.getByName(address.toString());
                        break;
                    }
                }

                //additionals/authorities used to be here



                //add answers and send
                List<DNSResourceRecord> answers = dnsPacket.getAnswers();
                if (answers.size() > 0) {

                    addAdditionalsAndAuths(dnsPacket, dnsPacketToSendToHost);

                    //add answers to the return packet
                    for (DNSResourceRecord record : answers) {
                        dnsPacketToSendToHost.addAnswer(record);
                    }

                    //send the return packet to client
                    sendToClient(dnsPacketToSendToHost, returnToSender);

                    //break while loop
                    run = false;
                }
            }


            System.out.println("Prepare for new query");

            //prepare new query
            dnsPacket.setQuery(true);
            dnsPacket.setRecursionAvailable(true);

            //System.out.println(dnsPacket.toString());

            List<DNSResourceRecord> additionals = dnsPacket.getAdditional();
            System.out.println("Removing " + additionals.size() + " additionals");
            int numAdds = additionals.size() - 1;
            for (int i = 0; i < numAdds; i++){
                dnsPacket.removeAdditional(dnsPacket.getAdditional().get(0));
               // System.out.println("Removing Additional");
                //System.out.println(additionals.get(i).toString());
            }

            //add authorities
            List<DNSResourceRecord> authorities = dnsPacket.getAuthorities();
            System.out.println("Removing " + authorities.size() + " authorities");
            int numAuths = authorities.size();
            for (int i = 0; i < numAuths; i++){
                dnsPacket.removeAuthority(dnsPacket.getAuthorities().get(0));
              //  System.out.println("Removing Authority");
               // System.out.println(authorities.get(i).toString());
            }

            //System.out.println(dnsPacket.toString());
            ttl--;
            System.out.println("TTL: " + ttl + "Run: " + run);
        }

        System.out.println("Close socket");

        socket.close();
    }

    private static void addAdditionalsAndAuths(DNS dnsPacket, DNS dnsPacketToSendToHost){
        //add additionals
        List<DNSResourceRecord> additionals = dnsPacket.getAdditional();
        int numAdds = additionals.size() - 1;
        System.out.println("Number of Additionals to be added: " + numAdds);
        for (int i = 0; i < numAdds; i++){
            dnsPacketToSendToHost.addAdditional(additionals.get(i));
            System.out.println("Adding additional: " + i);
        }

        //add authorities
        List<DNSResourceRecord> authorities = dnsPacket.getAuthorities();
        int numAuths = authorities.size();
        System.out.println("Number of Authorities to be added: " + numAuths);
        for (int i = 0; i < numAuths; i++){
            dnsPacketToSendToHost.addAuthority(authorities.get(i));
            System.out.println("Adding authority: " + i);
        }
    }

    private static void sendToClient(DNS dnsPacket, DatagramPacket returnToSener) throws IOException{

        //check IPv4 association with EC2 region
        if(dnsPacket.getQuestions().get(0).getType() == DNS.TYPE_A){

            //TODO
            //check if it is in the region

        }

        DatagramPacket answer = new DatagramPacket(dnsPacket.serialize(), dnsPacket.getLength(), returnToSener.getSocketAddress());
        serverSocket.send(answer);
        System.out.println("Responded with answer");
    }

    private static void readEC2File(String name) throws IOException{
        FileReader fileReader = null;
        BufferedReader reader = null;

        try {
            fileReader = new FileReader(name);
            reader = new BufferedReader(fileReader);


            String temp;
            while(true){
                temp = reader.readLine();

                if(temp == null){
                    //end of file reached
                    break;
                }

                String[] ip_location = temp.split(",");

                //TODO: do something with this stuffs

            }

            reader.close();
        }
        catch(FileNotFoundException e){
            e.printStackTrace();
            System.exit(-1);
        }

    }

    private static void matchPrefix(){
        String[] regions = {"72.44.32.0/19,Virginia","67.202.0.0/18,Virginia", "75.101.128.0/17,Virginia", "54.212.0.0/15,Oregon"};
        String stringIP = "54.212.0.0";
        int IP = 0;

        try {
            IP = ByteBuffer.wrap(InetAddress.getByName(stringIP).getAddress()).getInt();
        } catch (UnknownHostException e) {
            System.out.println("Unknown host");
            System.exit(-1);
        }

        boolean done = false;

        for(int i = 0; i < regions.length && !done; i++) {
            int ipIndex = regions[i].indexOf('/');
            int nameIndex = regions[i].indexOf(',');
            String regionStringIP = regions[i].substring(0, ipIndex);
            String regionName = regions[i].substring(nameIndex + 1);

            try {
                int regionIP = ByteBuffer.wrap(InetAddress.getByName(regionStringIP).getAddress()).getInt();

                //Get prefix length
                int prefixLen = Integer.parseInt(regions[i].substring(ipIndex + 1, nameIndex));

                //Create a mask
                long prefixMask = 0;
                for (int j = 32 - prefixLen; j < 32; j++) {
                    prefixMask += (1L << j);
                }

                if ((IP & prefixMask) == regionIP) {
                    //MATCH FOUND!!!!!!!!!!!
                    System.out.println("Match found for region: " + regionName);
                    done = true;
                }

            } catch (UnknownHostException e) {
                System.out.println("Unknown region host");
            }
        }

        if (!done) {
            System.out.println("No match found");
        }

    }
}
