#!/usr/bin/env python3
"""
Messenger app. Create users and groups and communicate with each other. Also several other functions
such as printing files and computing expressions have been implemented.

Usage: ./messenger [OPTION] ...

Options:
    -h, --help                              Print this message.

Commands:
    help                                    Print this message.
    Hello, Hi, Greet, Greetings             Greet the program and be greeted back (by name if logged in).
    x+a*y                                   With x,y,a being numbers. Prints out the result.
    say <output>                            Print out <output>.
    create
        - user <user>                       Create a new user with name <user>.
        - group <group> [<member1>,...]     Create a new group with name <group> and optionally <member1>,...
    add members to <group>: <member1>,...   Add the users <member1>,... to the group <group>.
    login <user>                            Login as user <user>.
    logout                                  Logout current user.
    print
        - <file>                            Print out the file <file>.
        - users                             Print out all users.
        - groups                            Print out all groups.
        - groups of <user>                  Print out all groups of the user <user>.
        - members of <group>                Print out all members of the group <group>.
    send to
        - <user>: <message>                 Send <message> to the user <user>.
        - <group>: <message>                Send <message> to the group <group>.
    sync                                    Synchronize messages. Print out messages received after login.
    delete
        - user <user>                       Delete the user <user>.
        - group <group>                     Delete the group <group>.
        - member from <group>: <member>     Delete the user <member> from the group <group>.

To quit the program type one of the following commands:
'stop', 'quit', 'cancel', 'q', 'end', ':q', 'exit'.
"""
import binascii
import getopt
import getpass
import hashlib
import pickle
import sys
import time
import os

# Global Variables

PATH = os.getcwd()
DATA = PATH + "/data"

def create_user(user):
    """Create a new user with hashed password.

    Args:
        user: Name of the new user.

    Raises:
        Error if passwords do not match.
    """
    if user_exists(user):
        print('A user with the name {} does already exist. Please choose a different username.'.format(user))
    else:
        password = getpass.getpass('Password: ')
        password_check = getpass.getpass('Repeat Password: ')
        if password != password_check:
            print('Passwords do not match. Try again.')
            create_user(user)
        else:
            salt = os.urandom(32)
            hashed_password = binascii.hexlify(hashlib.pbkdf2_hmac('sha256', str.encode(password), salt, 100000))
            d_pass = {}
            try:
                with open('{}/passes.txt'.format(DATA), 'rb') as file:
                    d_pass = pickle.load(file)
            except FileNotFoundError:
                print("File does not exist. Will be created...")
            d_pass[user] = [hashed_password, salt]
            with open('{}/passes.txt'.format(DATA), 'wb') as file:
                pickle.dump(d_pass, file)
            with open('{}/{}.txt'.format(DATA, user), 'wb') as file:
                d_user = {}
                d_user["messages"] = []
                d_user["groups"] = []
                pickle.dump(d_user, file)
            if not group_exists("all"):
                create_group("all", [user])
            else:
                add_members_to_group([user], "all")

def delete_user(user):
    """Delete a specified user.

    Args:
        user: Name of the user to be deleted.

    Raises:
        Error if no such user exists or the users password was wrong.
    """
    if not user_exists(user):
        print("This user {} does not exist.".format(user))
    else:
        password = getpass.getpass(user + "'s Password: ")
        try:
            with open('{}/passes.txt'.format(DATA), 'rb') as file:
                d_pass = pickle.load(file)
        except FileNotFoundError:
            print("No such user exists.")
        real_password = d_pass[user][0]
        salt = d_pass[user][1]
        hashed_password = binascii.hexlify(hashlib.pbkdf2_hmac('sha256', str.encode(password), salt, 100000))
        if hashed_password == real_password:
            groups = get_groups_of_member(user)
            if groups:
                for group in groups:
                    delete_member_from_group(user, group)
            d_pass.pop(user, None)
            with open(DATA + '/passes.txt', 'wb') as file:
                pickle.dump(d_pass, file)
            os.remove("{}/{}.txt".format(DATA, user))
            print("User {} has been deleted.".format(user))
        else:
            print("Invalid Password")

def delete_member_from_group(member, group):
    """Delete a specified user from a specific group.

    Args:
        member: name of the user whose membership is to be deleted.
        group: group from which the user is to be deleted.
    """
    if group_exists(group) and user_is_in_group(member, group):
        with open('{}/groups.txt'.format(DATA), 'rb') as file:
            d_group = pickle.load(file)
        d_group[group].remove(member)
        with open('{}/groups.txt'.format(DATA), 'wb') as file:
            pickle.dump(d_group, file)
        with open('{}/{}.txt'.format(DATA, member), 'rb') as file:
            d_user = pickle.load(file)
        d_user["groups"].remove(group)
        with open('{}/{}.txt'.format(DATA, member), 'wb') as file:
            pickle.dump(d_user, file)
        if not get_group_members(group):
            with open('{}/groups.txt'.format(DATA), 'rb') as file:
                d_group = pickle.load(file)
            d_group.pop(group, None)
            with open('{}/groups.txt'.format(DATA), 'wb') as file:
                pickle.dump(d_group, file)

def delete_group(group, user):
    """Delete specified group.

    Args:
        group: Group which is to be deleted.
        user: User who is about to delete the group.

    Raises:
        Error if user is not authorized to delete the group or if the group does not exist.
    """
    if group_exists(group) and user_is_in_group(user, group) and group != "all":
        with open('{}/groups.txt'.format(DATA), 'rb') as file:
            d_group = pickle.load(file)
        for member in d_group[group]:
            delete_member_from_group(member, group)
        d_group.pop(group, None)
        with open('{}/groups.txt'.format(DATA), 'wb') as file:
            pickle.dump(d_group, file)
        print("The group {} has been deleted.".format(group))
    else:
        print("You cannot delete the group {} (doesn't exist or you're not authorized).".format(group))

def user_is_in_group(member, group):
    """Check if specified user is member of a specific group.

    Args:
        user: User whose membership is to be checked.
        group: Group to which the membership is to be checked.

    Returns:
        True if user is in group, False otherwise.
    """
    res = False
    if group_exists(group):
        with open('{}/groups.txt'.format(DATA), 'rb') as file:
            d_group = pickle.load(file)
        if member in d_group[group]:
            res = True
    return res

def create_group(group, members):
    """Create a new group with specified members.

    Args:
        group: Name of the new group.
        members: List of members in this new group.

    Raises:
        Error if a group with the specified name does already exist or one specified member does not exist.
    """
    if group_exists(group):
        print("A group with this name does already exist. Please choose a different group name.")
    else:
        existing_members = []
        for member in members:
            if user_exists(member):
                existing_members.append(member)
                with open('{}/{}.txt'.format(DATA, member), 'rb') as file:
                    d_user = pickle.load(file)
                d_user["groups"].append(group)
                with open('{}/{}.txt'.format(DATA, member), 'wb') as file:
                    pickle.dump(d_user, file)
            else:
                print("User {0} not added: Does not exist. To create it type 'create user {0}'.".format(member))
        try:
            with open('{}/groups.txt'.format(DATA), 'rb') as file:
                d_group = pickle.load(file)
        except FileNotFoundError:
            print("Group file does not exist yet. Will be created...")
            d_group = {}
        d_group[group] = existing_members
        with open('{}/groups.txt'.format(DATA), 'wb') as file:
            pickle.dump(d_group, file)

def list_groups():
    """Print out a list of the existing groups.

    Raises:
        Error if there are no groups yet.
    """
    try:
        with open('{}/groups.txt'.format(DATA), 'rb') as file:
            d_group = pickle.load(file)
        for group in d_group:
            print(group)
    except FileNotFoundError:
        print("No groups")

def group_exists(group):
    """Check if specified group exists.

    Args:
        group: Name of the group whose existence is to be checked.

    Returns:
        True if group exists, False otherwise.
    """
    res = False
    try:
        with open('{}/groups.txt'.format(DATA), 'rb') as file:
            d_group = pickle.load(file)
        if group in d_group:
            res = True
    except FileNotFoundError:
        res = False
    return res

def get_group_members(group):
    """Return a list of the members of a specific group.

    Args:
        group: Name of the group whose members are to be returned.
    """
    members = []
    if group_exists(group):
        with open('{}/groups.txt'.format(DATA), 'rb') as file:
            d_group = pickle.load(file)
        members = d_group[group]
    return members

def list_group_members(group):
    """Print out the members of a specific group.

    Args:
        group: Name of the group whose members are to be printed.
    """
    members = get_group_members(group)
    for member in members:
        print(member)

def list_groups_of_member(member):
    """Print out the groups of a specified user.

    Args:
        member: Name of the user whose group memberships are to be printed.

    Raises:
        Error if user does not exist.
    """
    if user_exists(member):
        for group in get_groups_of_member(member):
            print(group)
    else:
        print("The user {} does not exist.".format(member))

def get_groups_of_member(member):
    """Return a list of groups of a specified user.

    Args:
        member: Name of the user whose group memberships are to be returned.
    """
    groups = []
    if user_exists(member):
        try:
            with open('{}/{}.txt'.format(DATA, member), 'rb') as file:
                d_user = pickle.load(file)
            if "groups" in d_user:
                groups = d_user["groups"]
        except FileNotFoundError:
            groups = []
    return groups

def add_members_to_group(members, group):
    """Add specified users to a specific group.

    Args:
        members: List of members to be added to the group.
        group: Name of the group to which the members are to be added.

    Raises:
        Error if user or group do not exist.
    """
    if group_exists(group):
        with open('{}/groups.txt'.format(DATA), 'rb') as file:
            d_group = pickle.load(file)
        for member in members:
            if user_exists(member):
                if member not in d_group[group]:
                    d_group[group].append(member)
                    with open('{}/{}.txt'.format(DATA, member), 'rb') as file:
                        d_user = pickle.load(file)
                    if "groups" not in d_user:
                        d_user["groups"] = []
                    d_user["groups"].append(group)
                    with open('{}/{}.txt'.format(DATA, member), 'wb') as file:
                        pickle.dump(d_user, file)
                else:
                    print("{} is already a member of {}".format(member, group))
            else:
                print("The user {} does not exist.".format(member))
        with open('{}/groups.txt'.format(DATA), 'wb') as file:
            pickle.dump(d_group, file)
    else:
        print("The group {} does not exist.".format(group))

def calc(exp):
    """Calculate given expression and return the result.

    Args:
        exp: Expression as string of the form a*x+b.
    """
    res = 0
    invalid = False
    adds = exp.split("+")
    for add in adds:
        mults = add.split("*")
        add = 1
        for mult in mults:
            if mult.isdigit():
                add = add*float(mult)
            else:
                print("calc: Invalid input. Only numbers, '+' and '*' allowed.")
                invalid = True
        res += add
    if invalid:
        res = None
    return res

def std_input(exp):
    """Check if the input is a number or an expression to be evaluated by the calc function.

    Args:
        exp: Expression that is either a number or of the form a*x+b.
    """
    try:
        res = float(exp)
        print(res)
    except ValueError:
        res = calc(exp)
        if res:
            print(res)

def say_hello(user):
    """Greet the user.

    Args:
        user: User that is to be greeted.
    """
    if user:
        print("Hello {}.".format(user))
    else:
        print("Hello.")

def say_x(exp):
    """Print out input.

    Args:
        exp: The input expression to be printed out.
    """
    print(exp)

def print_file(file_name):
    """Print out the contents of a specified file.

    Args:
        file_name: Path and name of the file to be printed.

    Raises:
        Error if file could not be found.
    """
    try:
        with open(file_name) as file:
            read_data = file.read()
            print(read_data)
    except FileNotFoundError:
        print("File was not found. Please make sure you typed it in the right way: /path/to/file/file_name")

def list_users():
    """Print out a list of the existing users."""
    if os.path.isfile('{}/passes.txt'.format(DATA)):
        with open('{}/passes.txt'.format(DATA), 'rb') as file:
            d_pass = pickle.load(file)
        for user in d_pass:
            print(user)

def get_users():
    """Return a list of the existing users."""
    users = []
    if os.path.isfile('{}/passes.txt'.format(DATA)):
        with open('{}/passes.txt'.format(DATA), 'rb') as file:
            d_pass = pickle.load(file)
        for user in d_pass:
            users.append(user)
    return users

def login(user):
    """Login as a specific user.

    Args:
        user: Name of the user to be logged in as.

    Raises:
        Error if password is not valid.
    """
    is_logged_in = False
    stop = False
    if not user_exists(user):
        print("The user {} does not exist. Do you want to create it?".format(user))
        answer = input("[y/n]: ")
        if answer == "y":
            create_user(user)
            print("Logging in as user " + user)
        else:
            stop = True
    if not stop:
        if not check_ticket(user):
            password = getpass.getpass('Password: ')
            with open('{}/passes.txt'.format(DATA), 'rb') as file:
                d_pass = pickle.load(file)
            real_password = d_pass[user][0]
            salt = d_pass[user][1]
            hashed_password = binascii.hexlify(hashlib.pbkdf2_hmac('sha256', str.encode(password), salt, 100000))
            if hashed_password == real_password:
                print(user + " logged in.")
                print_new_messages(user)
                update_ticket(user)
                is_logged_in = True
            else:
                print("Invalid Password")
        else:
            is_logged_in = True
            print(user + " logged in.")
            print_new_messages(user)
    return is_logged_in

def logout(user):
    """Logout specific user.

    Args:
        user: Name of the user to be logged out.
    """
    if user_exists(user):
        with open(DATA + '/.tickets.txt', 'rb') as file:
            d_time = pickle.load(file)
        d_time.pop(user, None)
        with open(DATA + '/.tickets.txt', 'wb') as file:
            pickle.dump(d_time, file)

def update_ticket(user):
    """Update ticket of the user after login.

    Args:
        user: Name of the user whose ticket is to be updated.
    """
    try:
        with open(DATA + '/.tickets.txt', 'rb') as file:
            d_time = pickle.load(file)
    except FileNotFoundError:
        d_time = {}
    d_time[user] = time.time()
    with open(DATA + '/.tickets.txt', 'wb') as file:
        pickle.dump(d_time, file)

def check_ticket(user):
    """Check if the current ticket is still valid (less than 30 minutes old).

    Args:
        user: Name of the user whose ticket is to be checked.

    Returns:
        True if ticket is still valid, False otherwise.
    """
    ticket = False
    try:
        with open(DATA + '/.tickets.txt', 'rb') as file:
            d_time = pickle.load(file)
        if user in d_time:
            delta = (time.time() - d_time[user])/60
            if delta < 30:
                ticket = True
    except FileNotFoundError:
        ticket = False
    return ticket

def user_exists(user):
    """Check if the specified user exists.

    Args:
        user: Name of the user whose existence is to be checked.

    Returns:
        True if user exists, False otherwise.
    """
    res = False
    try:
        with open('{}/{}.txt'.format(DATA, user), 'rb') as file:
            _ = pickle.load(file)
        res = True
    except FileNotFoundError:
        res = False
    return res

def send_message(sender, recipient, msg):
    """Send message to specified user or group.

    Args:
        sender: Name of the user who sends the message.
        recipient: Name of the recipient (user or group).
        msg: Content of the message.

    Raises:
        Error if sender or recipient do not exist.
    """
    if user_exists(sender) and user_exists(recipient):
        user_file = '{}/{}.txt'.format(DATA, recipient)
        with open(user_file, 'rb') as file:
            d_user = pickle.load(file)
        d_user["messages"].append(["From {}: {}".format(sender, msg), 1])
        with open(user_file, 'wb') as file:
            pickle.dump(d_user, file)
    elif group_exists(recipient):
        members = get_group_members(recipient)
        msg += " (sent to {})".format(recipient)
        for member in members:
            send_message(sender, member, msg)
    else:
        print("Recipient or sender does not exist.")

def print_messages(user):
    """Print the messages of the specified user.

    Args:
        user: Name of the user whose messages are to be printed.

    Raises:
        Error if user does not exist.
    """
    if user_exists(user):
        with open('{}/{}.txt'.format(DATA, user), 'rb') as file:
            d_user = pickle.load(file)
        if "messages" in d_user:
            for msg, _ in d_user["messages"]:
                print(msg)
        else:
            print("No messages.")
    else:
        print("User {} does not exist.".format(user))

def print_new_messages(user):
    """Print newly received messages since last login.

    Args:
        user: Name of the user whose messages are to be printed.
    """
    count = 0
    with open('{}/{}.txt'.format(DATA, user), 'rb') as file:
        d_user = pickle.load(file)
    if "messages" in d_user:
        for msg, number in d_user["messages"]:
            if number == 1:
                count += 1
                print(msg)
        d_user["messages"] = [[msg, no] if no == 0 else [msg, 0]  for msg, no in d_user["messages"]]
        with open('{}/{}.txt'.format(DATA, user), 'wb') as file:
            pickle.dump(d_user, file)
    if count == 0:
        print("No new messages.")

def rm_file(file_name):
    """Check if file exists and if so remove it.

    Args:
        file_name: Path and name of the file to be deleted.
    """
    if os.path.isfile(file_name):
        os.remove(file_name)

def main():
    """Set up command line interface and process input to call the corresponding functions."""
    if not os.path.isdir(DATA):
        os.mkdir(DATA)
    if len(sys.argv) == 1:
        print("Welcome to the messenger. Type 'quit' to exit and 'help' for more information about the usage.")
    try:
        opts = getopt.getopt(sys.argv[1:], "h", ["help"])[0]
    except getopt.GetoptError as err:
        print(__doc__)
        sys.exit(err)
    for opt, _ in opts:
        if opt in ["-h", "--help"]:
            sys.exit(__doc__)

    script = sys.argv[0].split("/").pop()[:-3]
    user = ""
    quits = ["stop", "quit", "cancel", "q", "end", ":q", "exit"]
    greets = ["hello", "hi", "greet", "greetings"]
    cmd_needs_arg = ["login", "say", "print", "create", "delete", "send", "add"]
    cmd_no_args = ["help", "logout", "sync"]
    cmd_no_args.extend(greets)
    cmd_no_args.extend(quits)
    if len(sys.argv) == 2:
        user = sys.argv[1]
        login(user)
    if user != "":
        prompt = "{}:{}# ".format(user, script)
    else:
        prompt = script + "# "

    while True:
        command = input(prompt)
        if not command:
            pass
        elif command.lower() in quits:
            if not get_users():
                rm_file(DATA + "/groups.txt")
                rm_file(DATA + "/passes.txt")
                rm_file(DATA + "/.tickets.txt")
                os.rmdir(DATA)
            break
        elif command[0].isdigit():
            std_input(command)
        elif command.lower() in greets:
            say_hello(user)
        elif command.lower() == "help":
            print(__doc__)
        elif command.lower() == "logout":
            logout(user)
            user = ""
            prompt = script + "# "
        elif command.lower() == "sync":
            if user_exists(user):
                print_new_messages(user)
            else:
                print("You need to be logged in to do this.")
        elif len(command.split()) > 1:
            inp = command.split()
            if inp[0].lower() == "say":
                for i in inp[1:]:
                    print(i + " ", end='')
                print("")
            elif inp[0].lower() == "print":
                if inp[1].lower() == "messages":
                    print_messages(user)
                elif inp[1].lower() == "users":
                    list_users()
                elif inp[1].lower() == "groups" and len(inp) == 2:
                    list_groups()
                elif inp[1].lower() == "groups" and len(inp) > 2:
                    list_groups_of_member(inp[3])
                elif inp[1].lower() == "members":
                    list_group_members(inp[3])
                else:
                    print_file(inp[1])
            elif inp[0].lower() == "login":
                if login(inp[1]):
                    user = inp[1]
                    prompt = "{}:{}# ".format(user, script)
            elif inp[0].lower() == "create":
                if inp[1].lower() == "user":
                    try:
                        create_user(inp[2])
                    except IndexError:
                        print("{}: No user name provided. Type 'help' for more information about the usage.".format(
                            inp[0].lower()))
                elif inp[1].lower() == "group":
                    try:
                        create_group(inp[2], inp[3:])
                    except IndexError:
                        print("{}: No group name provided. Type 'help' for more information about the usage.".format(
                            inp[0].lower()))
                else:
                    print("{}: Parameter not found. Type 'help' for more information about the usage.".format(
                        inp[1].lower()))
            elif inp[0].lower() == "delete":
                if inp[1].lower() == "user":
                    try:
                        delete_user(inp[2])
                    except IndexError:
                        print("{}: No user name provided. Type 'help' for more information about the usage.".format(
                            inp[0].lower()))
                elif inp[1].lower() == "group":
                    try:
                        delete_group(inp[2], user)
                    except IndexError:
                        print("{}: No group name provided. Type 'help' for more information about the usage.".format(
                            inp[0].lower()))
                elif inp[1].lower() == "member":
                    if user_exists(user):
                        try:
                            meta, memb = command.split(":")
                            grp = meta.split()[3]
                            delete_member_from_group(memb.strip(), grp)
                        except ValueError:
                            print("{}: Missing data. Type 'help' for more information about the usage.".format(
                                inp[0].lower()))
                    else:
                        print("You need to be logged in to do this.")
                else:
                    print("{}: Parameter not found. Type 'help' for more information about the usage.".format(
                        inp[1].lower()))
            elif inp[0].lower() == "send":
                try:
                    meta, msg = command.split(":")
                    if not msg or len(meta.split()) < 3:
                        print("{}: No recipient or message provided. Type 'help' for more information about the usage."
                              .format(inp[0].lower()))
                    else:
                        if msg[0] == " ":
                            msg = msg[1:]
                        recipient = meta.split()[2]
                        send_message(user, recipient, msg)
                except ValueError:
                    print("{}: Missing data. Type 'help' for more information about the usage.".format(
                        inp[0].lower()))
            elif inp[0].lower() == "add":
                if inp[1] == "members":
                    try:
                        meta, memb = command.split(":")
                        grp = meta.split()[3]
                        add_members_to_group(memb.split(), grp)
                    except ValueError:
                        print("{}: Missing data. Type 'help' for more information about the usage.".format(
                            inp[0].lower()))
                else:
                    print("{}: Parameter not found. Type 'help' for more information about the usage.".format(
                        inp[1].lower()))
            elif inp[0].lower() in cmd_no_args:
                print("{}: Command needs to be called without any arguments.".format(inp[0].lower()), end=" ")
                print("Type 'help' for more information about the usage.")
            else:
                print("{}: Command not found. Type 'help' for more information about the usage.".format(
                    command.lower()))
        elif command.lower() in cmd_needs_arg:
            print("{}: Command requires argument(s). Type 'help' for more information about the usage.".format(
                command.lower()))
        else:
            print("{}: Command not found. Type 'help' for more information about the usage.".format(command.lower()))

if __name__ == '__main__':
    main()
