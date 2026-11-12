#include <iostream>
#include <fstream>
#include <string>
#include <vector>

//This program is a simple SSH log file parser that extracts and categorizes events from the log file in failed and successful logins and preauths (attempted connections)
//To run the program, compile it and provide the path to the SSH log file as a command line argument. 
//The program will read the log file and extract relevant information and print it to the console.

//example usage: g++ -o ssh_log_parser ssh_log_parser.cpp
// ./ssh_log_parser.exe /var/log/auth.log


struct SSHevent {
    std::string timestamp;
    std::string type;
    std::string username;
    std::string ip;
};

std::string extractIP (const std::string& line){ //return type, const=read only, reference ->we can use . instead of ->, and we dont have to copy the whole string.
    std::size_t start = line.find(" from "); //find from in the string
    if (start != std::string::npos) { //if succeeds
        start += 6; //skip the " from "
        std::size_t end = line.find(' ', start);  //find where the ip ends
        return line.substr(start, end - start);  //return a substring starting at start pos andcopy end-start bytes
    }

    // Alternative format/preauth ... user robin IPadress port 1234"
    std::size_t portPos = line.find(" port "); //find port

    if (portPos != std::string::npos) { //if succeed
        std::size_t startIP = line.rfind(' ', portPos - 1); //search backwards from " port " -1 until end of IP

        if (startIP != std::string::npos) {
            return line.substr(startIP + 1, portPos - startIP - 1);
        }
    }

    return "Unknown";
}


std::string extractusername (const std::string& line){
    std::size_t start = line.find(" for "); //find " for "
    if (start != std::string::npos) {//if succeeds
        start += 5; // skip the " for "

        if (line.compare(start, 13, "invalid user ") == 0) { //if we find "invalid user " after " for ", push forward 13 chars
            start += 13;
        }
        std::size_t end = line.find(' ', start);
        return line.substr(start, end - start); //return substring starting at start pos and copy end-start bytes
    }

    // Alternative format/preauth . authenticating user robin .
    start = line.find("authenticating user ");

    if (start != std::string::npos) { // if found
        start += std::string("authenticating user ").length(); //skip the "authenticating user "
        std::size_t end = line.find(' ', start); //find end
        return line.substr(start, end - start); //return substring starting at start pos and copy end-start bytes
    }
    return "Unknown"; //otherwise return unknown
}

std::string extractTime (const std::string& line) {
    std::size_t end = line.find(' '); //as timestamp is always at beginning -> we just search for the end of it. 
    return line.substr(0, end);
}



void printEvents ( const std::string& title, const std::vector<SSHevent>& events){
    std::cout << "\n===" << title << "(" << events.size() << ")" <<"===\n";
    
    for ( const SSHevent& event : events) { //for each event in events -> we print all info.
        std::cout << "[" << event.timestamp << "] "
        << "User: " << event.username
        << " | IP: " << event.ip
        << " | Type: " << event.type
        << "\n";
    }


}




int main(int argc, char* argv[]) {
    
    if(argc < 2){ //1st arg is program, second we choose input file. If argc<2 this means we have no filepath
        std::cerr << "Error: No log file specified" << std::endl;
        return 1; //!=0 -> error
    }

    std::ifstream MyReadFile(argv[1]); //this takes our filepath as input and opens that file
    
    if(!MyReadFile.is_open()){ //if we cannot open file -> print error
        std::cerr << "Error: Could not open log file. Either file does not exist or permission denied." << std::endl;
        return 1; //returns not 0 which indicates an error
    }

    std::vector <SSHevent> failedLogins;
    std::vector <SSHevent> succesfulLogins;
    std::vector <SSHevent> connectionAttempts;

    std::string line; //define temporary string to hold lines

    // As long as lines are left, we keep reading
    while (std::getline(MyReadFile, line)) {
        SSHevent event; // initialize a new event for each line because we want to store each line as a new event.


        //if does not find -> sets max value, so we check if lower than big value -> it has found failed password
        if(line.find("Failed password") != std::string::npos){ 
            event.type = "Failed password"; //standard out, sends out the whole line and then adds a \n
        } 
        else if (line.find("Accepted password") != std::string::npos){
            event.type = "Accepted password";
        }else if (line.find("preauth") != std::string::npos)
        {
            event.type = "Preauth";
        }
        else {continue;} //if we do not a match for any of them -> skip to next line   
    
        //extract the rest of the info
        event.ip = extractIP(line);
        event.timestamp = extractTime(line);
        event.username = extractusername(line);
        


        if(event.type == "Failed password"){
            failedLogins.push_back(event);
        }else if(event.type == "Accepted password"){
            succesfulLogins.push_back(event);
        }else{
            connectionAttempts.push_back(event);
        }
    }

    printEvents("FAILED LOGINS", failedLogins);
    printEvents("SUCCESSFUL LOGINS", succesfulLogins);
    printEvents("PREAUTH EVENTS (attempted connetions)", connectionAttempts);

    MyReadFile.close();     
    return 0; //returns 0 which indicates success
}