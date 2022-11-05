#define _GNU_SOURCE
#include <ctype.h>
#include <openssl/md5.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define MAX_USERNAME_LENGTH 64
#define PASSWORD_LENGTH 6
#define NO_ALPHABET 26
#define MAX_THREADS 4

// global lock
pthread_mutex_t lock;

// number of password successfully cracked
int success = 0;

/************************* Part A *************************/
/**
 * This function generates combinations of 6 characters for potential password
 * following the combination of potentialPass
 * \param potentialPass[7]: an array of 7 char for 6 lower-case char and a null termintor
 * \return a string for the potential password
 */
char* cracking(char potentialPass[7]) {
  int position = 0;
  int z_reached = 0;

  while (position < 6) {
    if (potentialPass[position] != 'z' && z_reached == 0) {
      potentialPass[position] = potentialPass[position] + 1;
      return potentialPass;
    }  // if we have not reached any 'z', increment the char at the current position
    else if (potentialPass[position] != 'z' && z_reached == 1) {
      potentialPass[position] = potentialPass[position] + 1;
      for (int i = 0; i < position; i++) {
        potentialPass[i] = 'a';
      }
      return potentialPass;
    }  // if the current char is not 'z', and we have reached any 'z', increment the char at the
       // current position and set previous chars to 'a'
    else {
      z_reached = 1;
      position++;
    }  // if the current char is 'z', set z_reached to true, and increment position index
  }
  return potentialPass;
}

/**
 * Find a six character lower-case alphabetic password that hashes
 * to the given hash value. Complete this function for part A of the lab.
 *
 * \param input_hash  An array of MD5_DIGEST_LENGTH bytes that holds the hash of a password
 * \param output      A pointer to memory with space for a six character password + '\0'
 * \returns           0 if the password was cracked. -1 otherwise.
 */
int crack_single_password(uint8_t* input_hash, char* output) {
  char* potential_passwd;

  // Initialize candidate_passwd and set it to 'aaaaaa'
  char candidate_passwd[PASSWORD_LENGTH + 1];
  for (int i = 0; i < PASSWORD_LENGTH; i++) {
    candidate_passwd[i] = 'a';
  }

  // hashing candidate password
  uint8_t candidate_hash[MD5_DIGEST_LENGTH];
  MD5((unsigned char*)candidate_passwd, strlen(candidate_passwd), candidate_hash);

  // Iterate through possible password combinations until the hash values of the candidate password
  // and the input password match
  while (memcmp(input_hash, candidate_hash, MD5_DIGEST_LENGTH) != 0) {
    potential_passwd = cracking(candidate_passwd);
    MD5((unsigned char*)potential_passwd, strlen(potential_passwd), candidate_hash);
  }

  // Match! Copy the password to the output and return 0 (success)
  strncpy(output, potential_passwd, PASSWORD_LENGTH + 1);
  return 0;

  return -1;  // Fail to find a password
}

/********************* Parts B & C ************************/

/**
 * This struct is the root of the data structure that will hold users and hashed passwords.
 * This could be any type of data structure you choose: list, array, tree, hash table, etc.
 * Implement this data structure for part B of the lab.
 */
typedef struct node {
  struct node* next;
  char* user;
  uint8_t* hashPass;
} node_t;

/**This struct holds the head and the size of the password list */
typedef struct password_set {
  node_t* head;
  int size;
} password_set_t;

/**This struct holds the arguments needed for crack_by_thread*/
typedef struct thread_record {
  password_set_t* passwords;
  char start[PASSWORD_LENGTH + 1];
  char end[PASSWORD_LENGTH + 1];
} thread_record_t;

/**
 * Initialize a password set.
 * Complete this implementation for part B of the lab.
 *
 * \param passwords  A pointer to allocated memory that will hold a password set
 */
void init_password_set(password_set_t* passwords) {
  passwords->head = NULL;
  passwords->size = 0;
}

/**
 * Add a password to a password set
 * Complete this implementation for part B of the lab.
 *
 * \param passwords   A pointer to a password set initialized with the function above.
 * \param username    The name of the user being added. The memory that holds this string's
 *                    characters will be reused, so if you keep a copy you must duplicate the
 *                    string. I recommend calling strdup().
 * \param password_hash   An array of MD5_DIGEST_LENGTH bytes that holds the hash of this user's
 *                        password. The memory that holds this array will be reused, so you must
 *                        make a copy of this value if you retain it in your data structure.
 */
void add_password(password_set_t* passwords, char* username, uint8_t* password_hash) {
  if (passwords->head == NULL) {
    passwords->head = (node_t*)malloc(sizeof(node_t));
    passwords->head->user = strdup(username);
    passwords->head->hashPass = malloc(sizeof(uint8_t) * MD5_DIGEST_LENGTH);
    memcpy(passwords->head->hashPass, password_hash, MD5_DIGEST_LENGTH);
    passwords->head->next = NULL;
  }  // if passwords is empty, add to the head of the lsit
  else {
    node_t* newUser = (node_t*)malloc(sizeof(node_t));
    newUser->user = strdup(username);
    newUser->hashPass = malloc(sizeof(uint8_t) * MD5_DIGEST_LENGTH);
    memcpy(newUser->hashPass, password_hash, MD5_DIGEST_LENGTH);
    newUser->next = NULL;
    node_t* temp = passwords->head;
    passwords->head = newUser;
    newUser->next = temp;
  }  // else, add to the head of the list
  // update the size of the list
  passwords->size = passwords->size + 1;
}

/**
 * @brief Each thread will generate 1/6 of 26^6 combinations and compare the hash value of each
 * candidate password to each candidate combination. \param arg a thread_record_t thread holding
 * data of the passwords list, and the start and end combinations to consider
 *
 */
void* crack_by_thread(void* arg) {
  // cast our arg and extracting data fields
  thread_record_t* current_record = ((thread_record_t*)arg);
  node_t* storing = current_record->passwords->head;
  int numPass = current_record->passwords->size;
  char* potential_passwd;
  char candidate_passwd[PASSWORD_LENGTH + 1];
  strcpy(candidate_passwd, current_record->start);
  char stop_passwd[PASSWORD_LENGTH + 1];
  strcpy(stop_passwd, current_record->end);
  uint8_t candidate_hash[MD5_DIGEST_LENGTH];
  potential_passwd = candidate_passwd;

  // hash the first candidate password
  MD5((unsigned char*)candidate_passwd, strlen(candidate_passwd), candidate_hash);
  while (1) {
    while (storing != NULL) {
      if (memcmp(storing->hashPass, candidate_hash, MD5_DIGEST_LENGTH) == 0) {
        printf("%s %s\n", storing->user, potential_passwd);
        pthread_mutex_lock(&lock);
        success = success + 1;
        pthread_mutex_unlock(&lock);
      }  // If the hash values of the candidate password and input password match, print out the
         // strings and update success value
      storing = storing->next;
    }  // iterate through the passwords list

    // Generate and hash the next potentiol password
    potential_passwd = cracking(candidate_passwd);
    MD5((unsigned char*)potential_passwd, strlen(potential_passwd), candidate_hash);

    // break out of the loop after cracking all the password
    if (success == numPass) {
      break;
    }

    // Set storing string back to the beginning of passwords list
    storing = current_record->passwords->head;
    // end the loop after reaching the stop password
    if (strcmp(potential_passwd, stop_passwd) == 0) {
      break;
    }
  }  // while loop continues until we reach specific break conditions
  return NULL;
}

/**
 * Crack all of the passwords in a set of passwords. The function should print the username
 * and cracked password for each user listed in passwords, separated by a space character.
 * Complete this implementation for part B of the lab.
 *
 * \returns The number of passwords cracked in the list
 */
int crack_password_list(password_set_t* passwords) {
  // Initialze threads and treads_info arrays
  pthread_t threads[MAX_THREADS];
  thread_record_t threads_info[MAX_THREADS];

  // Initialize lock
  if (pthread_mutex_init(&lock, NULL) != 0) {
    perror("Lock cannot be initialized\n");
  }

  // Updating data fields for threads_info array, which will be used as arguments for
  // crack_by_thread
  for (int j = 0; j < MAX_THREADS; j++) {
    // passwords list
    threads_info[j].passwords = passwords;

    // Setting up start and end combinations
    char start_passwd[PASSWORD_LENGTH + 1];
    char end_passwd[PASSWORD_LENGTH + 1];

    for (int k = 0; k < PASSWORD_LENGTH; k++) {
      if (k == 5) {
        start_passwd[k] = (char)('a' + (j * 6));
        end_passwd[k] = (char)('a' + ((j + 1) * 6) - 1);
      } else {
        start_passwd[k] = 'a';
        end_passwd[k] = 'z';
      }
    }
    // set the null terminators
    start_passwd[6] = '\0';
    end_passwd[6] = '\0';

    strcpy(threads_info[j].start, start_passwd);
    strcpy(threads_info[j].end, end_passwd);
  }

  // Set the last stop string of the last thread to 'zzzzzz'
  threads_info[MAX_THREADS - 1].end[5] = 'z';

  // creating threads
  for (int i = 0; i < MAX_THREADS; i++) {
    if (pthread_create(&threads[i], NULL, crack_by_thread, &(threads_info[i])) != 0) {
      perror("Creating thread failed");
      return -1;
    }  // checking errors
  }

  // joining threads
  for (int l = 0; l < MAX_THREADS; l++) {
    if (pthread_join(threads[l], NULL) != 0) {
      perror("Joining threads failed");
      return -1;
    }  // checking errors
  }

  // Freeing nodes
  node_t* storing = passwords->head;
  node_t* temp;
  while (storing != NULL) {
    temp = storing->next;
    free(storing->user);
    free(storing->hashPass);
    free(storing);
    storing = temp;
  }
  return success;
}

/******************** Provided Code ***********************/

/**
 * Convert a string representation of an MD5 hash to a sequence
 * of bytes. The input md5_string must be 32 characters long, and
 * the output buffer bytes must have room for MD5_DIGEST_LENGTH
 * bytes.
 *
 * \param md5_string  The md5 string representation
 * \param bytes       The destination buffer for the converted md5 hash
 * \returns           0 on success, -1 otherwise
 */
int md5_string_to_bytes(const char* md5_string, uint8_t* bytes) {
  // Check for a valid MD5 string
  if (strlen(md5_string) != 2 * MD5_DIGEST_LENGTH) return -1;

  // Start our "cursor" at the start of the string
  const char* pos = md5_string;

  // Loop until we've read enough bytes
  for (size_t i = 0; i < MD5_DIGEST_LENGTH; i++) {
    // Read one byte (two characters)
    int rc = sscanf(pos, "%2hhx", &bytes[i]);
    if (rc != 1) return -1;

    // Move the "cursor" to the next hexadecimal byte
    pos += 2;
  }

  return 0;
}

void print_usage(const char* exec_name) {
  fprintf(stderr, "Usage:\n");
  fprintf(stderr, "  %s single <MD5 hash>\n", exec_name);
  fprintf(stderr, "  %s list <password file name>\n", exec_name);
}

int main(int argc, char** argv) {
  if (argc != 3) {
    print_usage(argv[0]);
    exit(1);
  }

  if (strcmp(argv[1], "single") == 0) {
    // The input MD5 hash is a string in hexadecimal. Convert it to bytes.
    uint8_t input_hash[MD5_DIGEST_LENGTH];
    if (md5_string_to_bytes(argv[2], input_hash)) {
      fprintf(stderr, "Input has value %s is not a valid MD5 hash.\n", argv[2]);
      exit(1);
    }

    // Now call the crack_single_password function
    char result[7];
    if (crack_single_password(input_hash, result)) {
      printf("No matching password found.\n");
    } else {
      printf("%s\n", result);
    }

  } else if (strcmp(argv[1], "list") == 0) {
    // Make and initialize a password set
    password_set_t passwords;
    init_password_set(&passwords);

    // Open the password file
    FILE* password_file = fopen(argv[2], "r");
    if (password_file == NULL) {
      perror("opening password file");
      exit(2);
    }

    int password_count = 0;

    // Read until we hit the end of the file
    while (!feof(password_file)) {
      // Make space to hold the username
      char username[MAX_USERNAME_LENGTH];

      // Make space to hold the MD5 string
      char md5_string[MD5_DIGEST_LENGTH * 2 + 1];

      // Make space to hold the MD5 bytes
      uint8_t password_hash[MD5_DIGEST_LENGTH];

      // Try to read. The space in the format string is required to eat the newline
      if (fscanf(password_file, "%s %s ", username, md5_string) != 2) {
        fprintf(stderr, "Error reading password file: malformed line\n");
        exit(2);
      }

      // Convert the MD5 string to MD5 bytes in our new node
      if (md5_string_to_bytes(md5_string, password_hash) != 0) {
        fprintf(stderr, "Error reading MD5\n");
        exit(2);
      }

      // Add the password to the password set
      add_password(&passwords, username, password_hash);
      password_count++;
    }

    // Now run the password list cracker
    int cracked = crack_password_list(&passwords);

    printf("Cracked %d of %d passwords.\n", cracked, password_count);

  } else {
    print_usage(argv[0]);
    exit(1);
  }

  return 0;
}
