def get_list_email_notify(list_email):
    # email_json = re.findall(r'"\s([^']*?)\s"')
    email_json = list_email
    print email_json


if __name__ == "__main__":
    get_list_email_notify(list_email="[u'admin@mvs.vn']")
