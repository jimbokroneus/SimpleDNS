package edu.wisc.cs.sdn.simpledns;

import edu.wisc.cs.sdn.simpledns.packet.*;


import java.io.BufferedReader;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.net.*;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.List;

public class SimpleDNS
{
    private final static int MAX_PACKET_SIZE = 1500;
    private final static int DNS_PORT = 53;
    private final static int LOCAL_DNS_PORT = 8053;
    private final static short TYPE_TXT = 16;

    /**
     * The Root DNS Server IP
     */
    private static String rootIp;

    /**
     * Name of the ec2 file
     */
    private static String ec2;

    /**
     * The main dns server socket
     */
    private static DatagramSocket serverSocket;

    /**
     * Holds region values read in from the passed in EC2 file
     */
    private static ArrayList<String> regions;

    //using this for our issues
    private static List<DNSResourceRecord> originalAdditionals;


    /**
     * Runs a simple DNS server
     * @param args "Usage: -r <root server ip> -e <ec2 csv>"
     */
    public static void main(String[] args)
    {
        System.out.println("Hello, DNS!");
        boolean run = true;

        //parse and validate args
        if (args.length != 4){
            System.out.println("Usage: -r <root server ip> -e <ec2 csv>");
            System.exit(-1);
        }

        rootIp = args[1];
        ec2 = args[3];
        regions = new ArrayList<String>();

        try {

            //read the passed in file
            readEC2File();


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
                        handlePacket(dnsPacket, packet);
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
    private static void handlePacket(DNS dnsPacket, DatagramPacket returnToSender) throws IOException{

        InetAddress inet = InetAddress.getByName(rootIp);
        DatagramSocket socket = new DatagramSocket();

        byte buff[] = new byte[MAX_PACKET_SIZE];
        DNS dnsPacketToSendToHost = dnsPacket;

        boolean run = true;
        int ttl = 100;

        System.out.println(inet);
        //System.out.println(socket.getRemoteSocketAddress().toString());

        originalAdditionals = new ArrayList<DNSResourceRecord>();
        originalAdditionals.addAll(dnsPacket.getAdditional());

        while(run && ttl>0) {

            System.out.println("*****************************************Start loop*****************************************");
            System.out.println("Sending packet: ");
            System.out.println(dnsPacket.toString());

            //Send Packet
            DatagramPacket nQuery = new DatagramPacket(dnsPacket.serialize(), 0, dnsPacket.getLength(), inet, DNS_PORT);
            socket.send(nQuery);

            //wait for the packet to be returned
            socket.receive(new DatagramPacket(buff, buff.length));
            dnsPacket = DNS.deserialize(buff, buff.length);

            System.out.println("Recieved packet: " + dnsPacket.toString());


            if (!dnsPacket.isRecursionDesired()) {
                System.out.println("No recursion desired");

                //send to client
                sendToClient(dnsPacketToSendToHost, returnToSender);
                run = false;

            } else {

                System.out.println("Recursion Desired");
                dnsPacket.setQuery(true);

                //select next server to send request to
                inet = selectNextServer(dnsPacket, inet);

                //add answers and send
                List<DNSResourceRecord> answers = dnsPacket.getAnswers();
                boolean cname = false;
                if (answers.size() > 0) {

                    addAdditionalsAndAuths(dnsPacket, dnsPacketToSendToHost);
                    short questionType = dnsPacket.getQuestions().get(0).getType();

                    //loop through all recorded answers checking for unresolved CNAMEs
                    for (DNSResourceRecord record : answers) {

                        dnsPacketToSendToHost.addAnswer(record);

                        if(record.getType() == DNS.TYPE_CNAME && questionType !=  DNS.TYPE_CNAME){
                            System.out.println("Answer was a CNAME. Checking if CNAME was resolved.");

                            cname = true;
                            //search through the records again for a answer to the CNAME
                            for(DNSResourceRecord r: answers){

                                System.out.println("Checking answers for CNAME resolution.");
                                System.out.println("Name: " + r.getName() + "Data: " + record.getData().toString());

                                if(r.getName().equals(record.getData().toString())){
                                    System.out.println("CNAME already resolved, sending to host");
                                    cname = false;
                                }
                            }

                            if(cname) {
                                List<DNSResourceRecord> resolvedCNAMEAnswer = resolveCname(dnsPacket, record.getData().toString());
                                System.out.println("resolveCname responded with: " + resolvedCNAMEAnswer);

                                if(resolvedCNAMEAnswer != null) {
                                    for(DNSResourceRecord r : resolvedCNAMEAnswer){
                                        dnsPacketToSendToHost.addAnswer(r);
                                    }
                                }
                            }

                        }
                    }

                    //send the return packet to client
                    sendToClient(dnsPacketToSendToHost, returnToSender);

                    //break while loop
                    run = false;

                }
            }

            System.out.println("DNS Packet: " + dnsPacket);

            if(run) {

                buildNextQuery(dnsPacket, null);

                //decrement ttl
                ttl--;

                System.out.println("TTL: " + ttl + "Run: " + run);
            }
        }

        System.out.println("Close socket");

        socket.close();
    }

    /**
     * Parses through the dnsPacket additionals, to select the next server to query
     *
     * @param dnsPacket the dns packet to parse
     * @param inet the inet to set (IP from the record)
     * @return inet
     * @throws IOException
     */
    private static InetAddress selectNextServer(DNS dnsPacket, InetAddress inet) throws IOException {
        List<DNSResourceRecord> additionals = dnsPacket.getAdditional();
//        if(additionals.size() == 1){
//            List<DNSResourceRecord> responseAdditionals = resolveAdditional(dnsPacket);
//
//            if(responseAdditionals != null) {
//                for (DNSResourceRecord record : responseAdditionals) {
//                    dnsPacket.addAdditional(record);
//                }
//            }
//
//        }

        for (DNSResourceRecord record : additionals) {
            if (record.getType() == DNS.TYPE_A) {
                DNSRdataAddress address = (DNSRdataAddress) record.getData();
                System.out.println("DNS Address: " + address);
                inet = InetAddress.getByName(address.toString());
                break;
            }
        }


        return inet;
    }

    private static List<DNSResourceRecord> resolveAdditional(DNS mdnsPacket) throws IOException{
        InetAddress inet = InetAddress.getByName(rootIp);
        DatagramSocket socket = new DatagramSocket();

        byte buff[] = new byte[MAX_PACKET_SIZE];
        boolean run = true;
        int ttl = 100;

        System.out.println(inet);
        //System.out.println(socket.getRemoteSocketAddress().toString());


        DNS dnsPacket = new DNS();

        //get authority from mdns
        List<DNSResourceRecord> authorities = mdnsPacket.getAuthorities();
        List<DNSQuestion> questions = new ArrayList<DNSQuestion>();
        questions.add(new DNSQuestion(authorities.get(0).getData().toString(), DNS.TYPE_A));
        dnsPacket.setQuestions(questions);

        dnsPacket.setQuestions(mdnsPacket.getQuestions());
        dnsPacket.setAdditional(originalAdditionals);
        dnsPacket.setId(mdnsPacket.getId());
        dnsPacket.setOpcode(mdnsPacket.getOpcode());
        dnsPacket.setRcode(mdnsPacket.getRcode());
        dnsPacket.setQuery(true);
        dnsPacket.setRecursionDesired(true);
        dnsPacket.setRecursionAvailable(true);

        System.out.println("DNS clone: " + dnsPacket);

        //buildNextQuery(dnsPacket, null);



        while(run && ttl>0) {
            System.out.println("*************************************Start loop in resolveAdditional*************************************");
            System.out.println("Sending packet:");
            System.out.println(dnsPacket.toString());

            //Send Packet
            DatagramPacket nQuery = new DatagramPacket(dnsPacket.serialize(), 0, dnsPacket.getLength(), inet, DNS_PORT);
            socket.send(nQuery);

            //wait for the packet to be returned
            socket.receive(new DatagramPacket(buff, buff.length));
            dnsPacket = DNS.deserialize(buff, buff.length);

            System.out.println("Recieved packet: " + dnsPacket.toString());


            System.out.println("Recursion Desired");
            dnsPacket.setQuery(true);

            //select next server to send request to
            inet = selectNextServer(dnsPacket, inet);


            //add answers and send
            List<DNSResourceRecord> answers = dnsPacket.getAnswers();
            if (answers.size() > 0) {
                return answers;
            }

            if (run) {

                buildNextQuery(dnsPacket, null);

                //decrement ttl
                ttl--;

                System.out.println("TTL: " + ttl + "Run: " + run);
            }

        }

        System.out.println("Close socket");

        socket.close();

        return null;
    }

    /**
     * Handles CNAME queries
     * @param mdnsPacket the packet containing the CNAME Answer
     * @param cname the url related the the CNAME
     * @return a list of resolved CNAME answers
     * @throws IOException
     */
    private static List<DNSResourceRecord> resolveCname(DNS mdnsPacket, String cname) throws IOException{
        InetAddress inet = InetAddress.getByName(rootIp);
        DatagramSocket socket = new DatagramSocket();

        byte buff[] = new byte[MAX_PACKET_SIZE];
        boolean run = true;
        int ttl = 100;

        System.out.println(inet);
        //System.out.println(socket.getRemoteSocketAddress().toString());

        DNS dnsPacket = new DNS();
        dnsPacket.setQuestions(mdnsPacket.getQuestions());
        dnsPacket.setAdditional(originalAdditionals);
        dnsPacket.setId(mdnsPacket.getId());
        dnsPacket.setOpcode(mdnsPacket.getOpcode());
        dnsPacket.setRcode(mdnsPacket.getRcode());
        dnsPacket.setQuery(true);
        dnsPacket.setRecursionDesired(true);
        dnsPacket.setRecursionAvailable(true);

        System.out.println("DNS clone: " + dnsPacket);

        buildNextQuery(dnsPacket, cname);



        while(run && ttl>0) {
            System.out.println("*************************************Start loop in resolveCname*************************************");
            System.out.println("Sending packet:");
            System.out.println(dnsPacket.toString());

            //Send Packet
            DatagramPacket nQuery = new DatagramPacket(dnsPacket.serialize(), 0, dnsPacket.getLength(), inet, DNS_PORT);
            socket.send(nQuery);

            //wait for the packet to be returned
            socket.receive(new DatagramPacket(buff, buff.length));
            dnsPacket = DNS.deserialize(buff, buff.length);

            System.out.println("Recieved packet: " + dnsPacket.toString());


            System.out.println("Recursion Desired");
            dnsPacket.setQuery(true);

            //select next server to send request to
            inet = selectNextServer(dnsPacket, inet);


            //add answers and send
            List<DNSResourceRecord> answers = dnsPacket.getAnswers();
            if (answers.size() > 0) {
                return answers;
            }

            if (run) {

                buildNextQuery(dnsPacket, null);

                //decrement ttl
                ttl--;

                System.out.println("TTL: " + ttl + "Run: " + run);
            }

        }

        System.out.println("Close socket");

        socket.close();

        return null;
    }

    /**
     * Sets up the dns packet for its next recursion
     * @param dnsPacket dns packet to prepare
     * @param cname the url of the cname we are querying.  Null if we are not querying a cname
     */
    private static void buildNextQuery(DNS dnsPacket, String cname) {
        System.out.println("Preparing the next query");

        //prepare new query
        dnsPacket.setQuery(true);
        dnsPacket.setRecursionAvailable(true);

        //remove additionals
        List<DNSResourceRecord> additionals = dnsPacket.getAdditional();
        System.out.println("Removing " + additionals.size() + " additionals");
        int numAdds = additionals.size() - 1;
        for (int i = 0; i < numAdds; i++) {
            dnsPacket.removeAdditional(dnsPacket.getAdditional().get(0));
            // System.out.println("Removing Additional");
            //System.out.println(additionals.get(i).toString());
        }

        //remove authorities
        List<DNSResourceRecord> authorities = dnsPacket.getAuthorities();
        System.out.println("Removing " + authorities.size() + " authorities");
        int numAuths = authorities.size();
        for (int i = 0; i < numAuths; i++) {
            dnsPacket.removeAuthority(dnsPacket.getAuthorities().get(0));
            //  System.out.println("Removing Authority");
            // System.out.println(authorities.get(i).toString());
        }

        if(cname != null){

            //set question
            DNSQuestion question = dnsPacket.getQuestions().get(0);
            question.setName(cname);

            //remove answers
            List<DNSResourceRecord> answers = dnsPacket.getAnswers();
            int numAns = answers.size();
            for (int i = 0; i < numAns; i++) {
                dnsPacket.removeAnswer(dnsPacket.getAnswers().get(0));
                //  System.out.println("Removing Authority");
                // System.out.println(authorities.get(i).toString());
            }


        }

    }

    /**
     * Adds all additionals and authorities to the specified packet
     * @param dnsPacket the packet we want to get the adds/auths from
     * @param dnsPacketToSendToHost the packet to add the adds/auths to
     */
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

    /**
     * Sends a packet to the original sender
     * @param dnsPacket dns packet to send
     * @param returnToSender datagram packet to send
     * @throws IOException
     */
    private static void sendToClient(DNS dnsPacket, DatagramPacket returnToSender) throws IOException{

        //check IPv4 association with EC2 region
        DNSQuestion question = dnsPacket.getQuestions().get(0);
        if(question.getType() == DNS.TYPE_A){

            //TODO
            matchPrefix(question.getName(), dnsPacket);

        }

        DatagramPacket answer = new DatagramPacket(dnsPacket.serialize(), dnsPacket.getLength(), returnToSender.getSocketAddress());
        serverSocket.send(answer);
        System.out.println("Responded with answer");
    }

    /**
     * Reads the specified file to get EC2 regions
     * The read values will be stored in the regions array list
     *
     * @throws IOException
     */
    private static void readEC2File() throws IOException{
        FileReader fileReader = null;
        BufferedReader reader = null;

        try {
            fileReader = new FileReader(ec2);
            reader = new BufferedReader(fileReader);


            String temp;
            while(true){
                temp = reader.readLine();

                if(temp == null){
                    //end of file reached
                    break;
                }

                regions.add(temp);

            }

            reader.close();
        }
        catch(FileNotFoundException e){
            e.printStackTrace();
            System.exit(-1);
        }

    }

    /**
     * Searches for a best mach between the IP prefix and EC2 regions.
     * Adds the TXT answer to the toReturnToSender packet's answers list.
     *
     * @param dnsName dns packet we are trying to match
     * @param toReturnToSender dns pacekt that will be returned to the sender
     */
    private static void matchPrefix(String dnsName, DNS toReturnToSender){
        //String[] regions = {"72.44.32.0/19,Virginia","67.202.0.0/18,Virginia", "75.101.128.0/17,Virginia", "54.212.0.0/15,Oregon"};

        List<DNSResourceRecord> tempList = new ArrayList<DNSResourceRecord>();
        for(DNSResourceRecord answer : toReturnToSender.getAnswers()) {

            if(answer.getType() != DNS.TYPE_A){
                continue;
            }

            String stringIP = answer.getData().toString();
            int IP = 0;

            try {
                IP = ByteBuffer.wrap(InetAddress.getByName(stringIP).getAddress()).getInt();
            } catch (UnknownHostException e) {
                System.out.println("Unknown host");
                System.exit(-1);
            }

            boolean done = false;

            for (int i = 0; i < regions.size() && !done; i++) {
                int ipIndex = regions.get(i).indexOf('/');
                int nameIndex = regions.get(i).indexOf(',');
                String regionStringIP = regions.get(i).substring(0, ipIndex);
                String regionName = regions.get(i).substring(nameIndex + 1);

                try {
                    int regionIP = ByteBuffer.wrap(InetAddress.getByName(regionStringIP).getAddress()).getInt();

                    //Get prefix length
                    int prefixLen = Integer.parseInt(regions.get(i).substring(ipIndex + 1, nameIndex));

                    //Create a mask
                    long prefixMask = 0;
                    for (int j = 32 - prefixLen; j < 32; j++) {
                        prefixMask += (1L << j);
                    }

                    if ((IP & prefixMask) == regionIP) {
                        //MATCH FOUND!!!!!!!!!!!
                        System.out.println("Match found for region: " + regionName);

                        //create TXT record and add to answers
                        DNSResourceRecord txtRecord = new DNSResourceRecord();
                        txtRecord.setName(dnsName);
                        txtRecord.setType(TYPE_TXT);

                        DNSRdataString location = new DNSRdataString(regionName + "-" + regionStringIP);
                        txtRecord.setData(location);

                        tempList.add(txtRecord);

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

        for(DNSResourceRecord ans : tempList){
            toReturnToSender.addAnswer(ans);
        }

    }
}
