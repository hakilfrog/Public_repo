import random
import datetime

import hashlib


class Group:
    name = ''
    rights = list()

    def __init__(self, name, rights):
        self.name = name
        self.rights = rights


class Account:
    username = ''
    password = ''
    groups: list[Group] = list()

    def __init__(self, username, password, groups):
        self.username = username
        self.password = hashlib.md5(password.encode()).hexdigest()  # хешируем пароль
        self.groups = groups


class NoAccount:
    login: str = ''
    password: str = ''
    int: int
    request: str

    def init(self, login, password, request):
        self.login = login
        self.password = password
        self.request = request
        self.int = 0  # интерфейс пользователя (1 - CLI, 0 - просто)

    def cli_itin(self):
        self.login = input('Введите логин ')
        self.password = hashlib.md5(input('Введите пароль ').encode()).hexdigest()
        self.int = 1


def gen_users():
    users = list()
    for user in range(20):
        user = Account(username='u_' + str(random.randint(10, 99)), password='p_' + str(random.randint(100, 999)),
                       groups=[cli.groupuser])
        users.append(user)
    return users


class Database:
    accounts: list[Account] = list()
    groups: list[Group] = list()

    def gen_users(self):
        self.accounts = gen_users()

    def get_accounts(self):
        return self.accounts

    def add_account(self, account):
        self.accounts.append(account)

    def add_group(self, group):
        self.groups.append(group)

    def output(self):
        count = 1
        for account in self.get_accounts():
            print(count, ' | USER: ', account.username, '\t| HASH_PASS: ', account.password, '\t |\tGROUP (if any):',
                  end=' ')
            for group in account.groups:
                print(group.name, end=' | ')
            print()
            count += 1


class AuthentificationError(Exception):
    pass


class AuthorizationError(Exception):
    pass


class Registration:
    new_login: str
    new_password: str
    def_group: list[Group] = []
    he_login: str
    he_password: str

    def __init__(self):
        self.new_login = input("Enter login: ")
        self.new_password = input("Enter password: ")
        # проверяем, что при регистрации нет пользователя с таким же юзернеймом
        login_exists = any(account.username == self.new_login for account in cli.db.accounts)

        if not login_exists:          # 🔽🔽 здесь обрабатываем пароль, перед добавлением в базу
            cli.db.add_account(account=Account(self.new_login, self.new_password, [cli.groupuser]))
        else:
            print("Account already exists . . . ")


class CLIUserInput:
    login: str
    password: str
    resource_request: str = None

    def begin_user_interaction(self, some_noaccount):
        some_noaccount = NoAccount()
        some_noaccount.cli_itin()
        return some_noaccount

    def user_interaction(self, account, resource_request):
        self.resource_request = input("Введите необходимое действие: ")
        return self.resource_request


class CLIUserStub(CLIUserInput):

    def begin_user_interaction(self, login='l', password='p', request='kill'):
        some_noaccaunt = NoAccount()
        some_noaccaunt.init(login, password, request)
        return some_noaccaunt

    def user_interaction(self, account, resource_request=None):
        if resource_request is None:
            resource_request = input("Ваш запрос:")
        self.resource_request = resource_request
        return account, resource_request


class Authentication:
    noaccount: NoAccount
    us_username: str
    us_password: str
    status = False
    statusl = True
    statusp = True

    def __init__(self, noaccount):
        self.noaccount = noaccount

    def credentials_check(self, database):

        try:
            for account in database.accounts:
                if self.noaccount.login == account.username:
                    self.statusl = True

                    if self.noaccount.password == account.password:
                        self.statusp = True
                        self.status = True
                        print("--> Аутентификация прошла успешно <--")
                        cli.audit.add_incident(
                            Incident(self.noaccount.login, datetime.datetime.now(), status=self.statusp,
                                     action="login"))
                        cli.audit.add_incident(
                            Incident(self.noaccount.login, datetime.datetime.now(), status=self.statusp,
                                     action="password"))
                        if self.noaccount.int == 0:
                            cli.authorize.access_check(account, self.noaccount.request)
                        else:
                            cli.authorize.access_check(account, cli.interfaceU.user_interaction(account, None))
                        break

                    else:
                        self.statusp = False
                        break

                else:
                    self.statusl = False

            if not self.statusl:
                cli.audit.add_incident(
                    Incident(self.noaccount.login, datetime.datetime.now(), status=self.statusl, action="login"))
                raise AuthentificationError("!--> Неправильный логин или пароль <--!")
            elif not self.statusp:
                if self.statusl:
                    cli.audit.add_incident(
                        Incident(self.noaccount.login, datetime.datetime.now(), status=self.statusl,
                                 action="login"))
                    cli.audit.add_incident(
                        Incident(self.noaccount.login, datetime.datetime.now(), status=self.statusp,
                                 action="password"))
                    raise AuthentificationError("!--> Неправильный логин или пароль <--!")
            elif self.statusl:
                pass  # так надо не спрашивай
            else:
                cli.audit.add_incident(
                    Incident(self.noaccount.login, datetime.datetime.now(), status=self.statusp, action="password"))

        except AuthentificationError:
            print("!--> Неправильный логин или пароль <--!")


class Authorization:
    status = 2

    def access_check(self, account, resource_request):
        if len(account.groups) > 0:
            for group in account.groups:
                if resource_request in group.rights:
                    print("Доступ разрешён!")
                    cli.audit.add_incident(Incident(user_name=account.username, time=datetime.datetime.now(),
                                                    status='True', action=f"Authorized to {resource_request}"))
                    break
                else:  # в каких-то хоть группах
                    for db_group in cli.db.groups:
                        if resource_request in db_group.rights:
                            self.status = 1
                            break
            if self.status == 1:
                print("Нет прав для выполнения")
                cli.audit.add_incident(Incident(user_name=account.username, time=datetime.datetime.now(),
                                                status=False, action=f"Authorized to {resource_request}"))
            elif self.status == 2:
                print("Нет такого действия")
                cli.audit.add_incident(Incident(user_name=account.username, time=datetime.datetime.now(),
                                                status=False, action=f"Authorized to {resource_request}"))
        else:
            print("Нет прав для выполнения")
            cli.audit.add_incident(Incident(user_name=account.username, time=datetime.datetime.now(),
                                            status=False, action=f"Authorized to {resource_request}"))
        self.status = 2


class Incident:
    username: Account
    time: datetime
    status: bool
    action: str

    def __init__(self, user_name, time, status, action):
        self.username = user_name
        self.time = time
        self.status = status
        self.action = action


class Audit:
    incidents: list[Incident] = list()

    def get_incidents(self):
        for incident in self.incidents:
            if incident.status:
                print(f'<------------------> {incident.time} | user: \'{incident.username}\' | action: '
                      f'{incident.action} | ip: 127.0.0.1 <----------------->')
            else:
                print(f'<####-ERROR-#######> {incident.time} | user: \'{incident.username}\' | action: '
                      f'{incident.action} | ip: 127.0.0.1 <#################>')

    def add_incident(self, incident):
        self.incidents.append(incident)


class CLI:
    def __init__(self):  # здесь можно менять параметры под нужные:
        self.audit = Audit()
        ###
        self.db = Database()
        ###
        self.authorize = Authorization()
        ###
        self.noaccountmain = NoAccount()
        ###
        self.groupadmin = Group(name='groupadmin',
                                rights=['kill', 'word'])
        self.groupuser = Group(name='users',
                               rights=['google', 'ya.oru'])
        self.db.add_group(self.groupadmin)
        self.db.add_group(self.groupuser)
        ###
        # db.gen_users()
        ###
        testuser = Account(username='l',
                           password='p',
                           groups=[self.groupadmin, self.groupuser])
        someuser = Account(username='lol', password='p', groups=[])  # groupuser])
        self.db.add_account(testuser)
        self.db.add_account(someuser)
        ###
        # self.db.output()
        ###
        self.interfaceU = CLIUserInput()

    def main_choise(self):
        us_opt = input("Type 1 for interaction, 2 for dev: ")
        if us_opt == '1':
            while us_opt != 'q':
                us_choice = input("Type 1 for sign up, 2 for login and 'q' for return: ")
                if us_choice == '1':
                    reg = Registration()
                elif us_choice == '2':
                    a = Authentication(self.interfaceU.begin_user_interaction(some_noaccount=self.noaccountmain))
                    while us_choice != 'q':
                        a.credentials_check(self.db)
                        us_choice = input("\nType 'q' for return, Enter for continue: ")
                elif us_choice == 'q':
                    us_opt = 'q'

        elif us_opt == '2':
            while us_opt != 'q':
                dev_choice = input("1 for get incidents, 2 for get user database, 3 for return, 'out' for end the "
                                   "program: ")
                if dev_choice == '1':
                    self.audit.get_incidents()
                elif dev_choice == '2':
                    self.db.output()
                elif dev_choice == '3':
                    us_opt = 'q'
                elif dev_choice == 'out':
                    exit()

    def start_madness(self):
        while True:
            self.main_choise()


########################################################################################################################


cli = CLI()
cli.start_madness()
