// UserDatabase.cpp
#include "UserDatabase.h"

UserDatabase::UserDatabase() {
    // Initialize the database or load existing data
}

bool UserDatabase::addUser(const std::string& username, const std::string& password) {
    if (userExists(username)) {
        return false; // User already exists
    }
    userDatabase[username] = password; // Store password (consider hashing in real implementation)
    return true;
}

bool UserDatabase::userExists(const std::string& username) {
    return userDatabase.find(username) != userDatabase.end();
}

std::string UserDatabase::getUserPassword(const std::string& username) {
    if (userExists(username)) {
        return userDatabase[username];
    }
    return ""; // Return empty string if user does not exist
}