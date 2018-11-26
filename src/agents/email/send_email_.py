# -*- coding: utf-8 -*-

# Send an HTML email with an embedded image and a plain text message for
# email clients that don't want to display the HTML.
import smtplib

from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.image import MIMEImage
from email import Charset


def send_email(user, pwd, recipient, cc, bcc, subject, html):
    # Define these once; use them twice!
    strFrom = user
    strTo = [recipient,cc,bcc]

    # Create the root message and fill in the from, to, and subject headers
    msgRoot = MIMEMultipart('related')
    msgRoot['Subject'] = subject
    msgRoot['From'] = user
    msgRoot['To'] = recipient
    msgRoot['Cc']=cc
    msgRoot['Bcc']= bcc
    msgRoot.preamble = 'This is a multi-part message in MIME format.'

    # Encapsulate the plain and HTML versions of the message body in an
    # 'alternative' part, so message agents can decide which they want to display.
    msgAlternative = MIMEMultipart('alternative')
    msgRoot.attach(msgAlternative)

    msgText = MIMEText('This is the alternative plain text message.')
    msgAlternative.attach(msgText)

    # We reference the image in the IMG SRC attribute by the ID we give it below
    msgText = MIMEText(html, 'html', 'UTF-8')
    msgAlternative.attach(msgText)

    listDic_image = ['logo_img.png', 'ethernet.png', 'analytics.png']

    x = 1
    for i in listDic_image:
        fp = open(str(i), 'rb')
        msgImage = MIMEImage(fp.read())
        fp.close()

        img_name = '<image' + str(x) + '>'       
        msgImage.add_header('Content-ID', img_name)

        x += 1
        msgRoot.attach(msgImage)

    # Send the email (this example assumes SMTP authentication is required)
    try:
        smtp = smtplib.SMTP('smtp.gmail.com', 587)
        smtp.ehlo()
        smtp.starttls()
        smtp.login(user, pwd)
        smtp.sendmail(user, [recipient], msgRoot.as_string())
        print(smtp.sendmail(user, [recipient], msgRoot.as_string()))
        smtp.quit()
        print("Successfully sent email")

    except:
        print("Error: unable to send email")


if __name__ == '__main__':
    # recipient = 'ngocngoan060288@hotmail.com' + ',' + 'ngocngoan060288@gmail.com'
    cc='ngocngoan060288@gmail.com'
    bcc='ngocngoan060288@hotmail.com'
    recipient = 'ducbvbk@gmail.com'
    send_email('ducbvbk@gmail.com', 'bm123456!', recipient, cc, bcc, 'Ngoc Ngoan test UTF-8',
           u"""\
           <!DOCTYPE html>
           <html lang="en">
           <head>
             <meta charset="UTF-8">
             <title>Ít lỗi</title></head>
           <body>
           <table width="100%" border="0" cellspacing="0" cellpadding="0"
       style="table-layout:fixed;background-color: #f2f4f6;font-family:Roboto-Regular,Helvetica,Arial,sans-serif;">
  <tbody>
  <tr>
    <td align="center">
      <table width="100%" style="table-layout:fixed;min-width:348px" border="0" cellspacing="0" cellpadding="0">
        <tbody>
        <tr>
          <td height="8"></td>
        </tr>
        <tr align="center">
          <td>
            <table border="0" cellspacing="0" cellpadding="0" style="table-layout:fixed;max-width:600px;background-color: #FFFFFF;">
              <tbody>
              <tr>
                <td height="16"></td>
              </tr>

              <tr>
                <td>
                  <table width="100%" border="0" cellspacing="0" cellpadding="0" style="table-layout:fixed;">
                    <tbody>
                    <tr>
                      <td width="24"></td>
                      <td align="left">
			<a href="http://securitybox.vn/" target="_blank">
                          <img style="display:block;"
                               src="cid:image1" width="150"
                               alt="SecurityBox Logo" border="0">
			</a>
                      </td>
                      <td align="right"></td>
                    </tr>
                    </tbody>
                  </table>
                </td>
              </tr>

              <tr>
                <td height="16"></td>
              </tr>

              <tr>
                <td>
                  <table bgcolor="#4184F3" width="100%" border="0" cellspacing="0" cellpadding="0"
                         style="table-layout:fixed;min-width:332px;max-width:600px;border:1px solid #f0f0f0;border-bottom:0;background-color:#00994D">
                    <tbody>
                    <tr>
                      <td height="20"></td>
                    </tr>
                    <tr>
                      <td
                        style="font-size:18px;font-weight:bold;color:#ffffff;line-height:1;min-width:300px;text-align: center">
                        BÁO CÁO TÌNH TRẠNG AN NINH HỆ THỐNG
                      </td>
                    </tr>
                    <tr>
                      <td height="20"></td>
                    </tr>
                    </tbody>
                  </table>
                </td>
              </tr>

              <tr>
                <td>
                  <table bgcolor="#FFFFFF" width="100%" border="0" cellspacing="0" cellpadding="0"
                         style="table-layout:fixed;min-width:332px;max-width:600px;border-bottom:1px solid #c0c0c0;">
                    <tbody>
                    <tr>
                      <td width="24"></td>
                      <td>
                        <table style="table-layout:fixed;min-width:300px;width:100%;" border="0" cellspacing="0" cellpadding="0">
                          <tbody>
                          <tr>
                            <td height="20"></td>
                          </tr>
                          <tr>
                            <td style="font-size:13px;color:#202020;line-height:1.5;">
                              Kính gửi anh(chị) Hoàng Mạnh Ngọc!
                              <br>
                              Dịch vụ kiểm tra an ninh mạng
                              <strong>SecurityBox 4Network</strong>
                              xin thông báo kết quả kiểm tra an ninh.
                              <br><br>
                            </td>
                          </tr>
                          <tr>
                            <td style="font-size:13px;color:#202020;line-height:1.5;"
                                align="center" width="100%">
                              <table border="0" cellspacing="0" cellpadding="0" width="100%" style="table-layout:fixed">
                                <tbody>
                                <tr>
                                  <td width="25%"></td>
                                  <td style="border:#00994D 1px solid;">
                                    <table border="0" cellspacing="0" cellpadding="0" width="100%"
                                           style="table-layout:fixed;">
                                      <tbody>
                                      <tr>
                                        <td height="5"></td>
                                      </tr>
                                      <tr>
                                        <td width="100%" align="center">
                                          <a href="http://dantri.com.vn/" target="_blank"
                                             style="width:100%;text-decoration:none;color:#00994D;line-height:22px;display:block;font-size: 18px;font-weight:bold;">
                                            Báo cáo chi tiết
                                          </a>
                                        </td>
                                      </tr>
                                      <tr>
                                        <td height="5"></td>
                                      </tr>
                                      </tbody>
                                    </table>
                                  </td>
                                  <td width="25%"></td>
                                </tr>
                                <tr>
                                  <td height="20"></td>
                                </tr>
                                </tbody>
                              </table>
                            </td>
                          </tr>
                          </tbody>
                        </table>
                      </td>
                      <td width="24"></td>
                    </tr>
                    </tbody>
                  </table>
                </td>
              </tr>

              <tr>
                <td height="10" style="background-color: #f2f4f6;"></td>
              </tr>

              <tr>
                <td align="center">
                  <table border="0" cellpadding="0" cellspacing="0" width="100%" style="table-layout:fixed">
                    <tbody>
                    <tr>
                      <td height="20"></td>
                    </tr>
                    <tr>
                      <td width="41%"></td>
                      <td width="2%"></td>
                      <td align="center" width="50">
                        <img src="cid:image2" style="display:block;" height="50" width="50">
                      </td>
                      <td width="2%"></td>
                      <td width="41%"></td>
                    </tr>
                    </tbody>
                  </table>
                </td>
              </tr>

              <tr>
                <td height="10"></td>
              </tr>

              <tr>
                <td style="font-weight:600;color:#212121;font-size:16px;line-height:20px" align="center">
                  Địa chỉ quét
                </td>
              </tr>
              <tr>
                <td height="10"></td>
              </tr>

              <tr>
                <td>
                  <table bgcolor="#FFFFFF" width="100%" border="0" cellspacing="0" cellpadding="0"
                         style="table-layout:fixed;min-width:332px;max-width:600px;border:0;border-bottom:1px solid #c0c0c0;">
                    <tbody>
                    <tr>
                      <td width="32" rowspan="3"></td>
                      <td></td>
                      <td width="32" rowspan="3"></td>
                    </tr>

                    <tr>
                      <td>
                        <table style="table-layout:fixed;min-width:300px;width:100%;"
                               border="0" cellspacing="0" cellpadding="0">
                          <tbody>
                          <tr>
                            <td>
                              <table border="0" cellpadding="0" cellspacing="0" width="100%"
                                     style="table-layout:fixed">
                                <tbody>
                                <tr>
                                  <td>
                                    <table border="0" cellpadding="0" cellspacing="0" width="100%"
                                           style="table-layout:fixed">
                                      <tbody>
                                      <tr>
                                        <td width="100%">
                                          <table border="0" cellpadding="0" cellspacing="0" width="100%"
                                                 style="table-layout:fixed">
                                            <tbody>
                                            <tr>
                                              <td width="2%"></td>
                                              <td width="64%" align="center"
                                                  style="background-color:#ffffff;border:#d4d4d4 1px solid">
                                                <table border="0" cellpadding="0" cellspacing="0" width="100%"
                                                       style="table-layout:fixed">
                                                  <tbody>
                                                  <tr>
                                                    <td
                                                      style="font-weight:700;font-size:18px;color:#212121;line-height:30px"
                                                      align="center">123.45.67.89
                                                    </td>
                                                  </tr>
                                                  <tr>
                                                    <td
                                                      style="font-weight:700;font-size:18px;color:#212121;line-height:30px"
                                                      align="center">123.45.67.89
                                                    </td>
                                                  </tr>
                                                  </tbody>
                                                </table>
                                              </td>
                                              <td width="2%"></td>
                                            </tr>
                                            </tbody>
                                          </table>
                                        </td>
                                      </tr>
                                      </tbody>
                                    </table>
                                  </td>
                                </tr>
                                </tbody>
                              </table>
                            </td>
                          </tr>
                          <tr>
                            <td height="20"></td>
                          </tr>
                          </tbody>
                        </table>
                      </td>
                    </tr>
                    </tbody>
                  </table>
                </td>
              </tr>

              <tr>
                <td height="10" style="background-color: #f2f4f6;"></td>
              </tr>

              <tr>
                <td align="center">
                  <table border="0" cellpadding="0" cellspacing="0" width="100%" style="table-layout:fixed">
                    <tbody>
                    <tr>
                      <td height="10"></td>
                    </tr>
                    <tr>
                      <td width="41%"></td>
                      <td width="2%"></td>
                      <td align="center" width="50">
                        <img src="cid:image3" style="display:block;"
                             height="50" width="50">
                      </td>
                      <td width="2%"></td>
                      <td width="41%"></td>
                    </tr>
                    </tbody>
                  </table>
                </td>
              </tr>

              <tr>
                <td height="10"></td>
              </tr>

              <tr>
                <td style="font-weight:600;color:#212121;font-size:16px;line-height:20px" align="center">
                  Số lượng lỗ hổng đã phát hiện
                </td>
              </tr>

              <tr>
                <td height="20"></td>
              </tr>

              <tr>
                <td>
                  <table bgcolor="#FFFFFF" width="100%" border="0" cellspacing="0" cellpadding="0"
                         style="table-layout:fixed;min-width:332px;max-width:600px;border:0;border-bottom:1px solid #c0c0c0;">
                    <tbody>
                    <tr>
                      <td width="32"></td>
                      <td>
                        <table style="table-layout:fixed;min-width:300px;width:100%;"
                               border="0" cellspacing="0" cellpadding="0">
                          <tbody>
                          <tr>
                            <td width="100%" style="font-size:14px;color:#202020;line-height:1.5;">
                              <table border="0" cellpadding="0" cellspacing="0" width="100%"
                                     style="table-layout:fixed;">
                                <tbody>
                                <tr>
                                  <td width="2%"></td>
                                  <td width="49%" align="center"
                                      style="background-color:#ffffff;border:#d4d4d4 1px solid">
                                    <table border="0" cellpadding="0" cellspacing="0" width="100%"
                                           style="table-layout:fixed">
                                      <tbody>
                                      <tr>
                                        <td align="center">
                                          <strong style="display:inline-block; color: #d43f3a; font-size: 50px;">
                                            12
                                          </strong>
                                        </td>
                                      </tr>
                                      <tr>
                                        <td style="font-size:14px;color:#212121;line-height:18px;"
                                            align="center" height="30">Lỗ hổng cấp độ
                                        </td>
                                      </tr>
                                      <tr>
                                        <td height="10"></td>
                                      </tr>
                                      <tr>
                                        <td style="font-size:20px;color:#212121;line-height:18px;"
                                            align="center"><b>Nguy hiểm</b>
                                        </td>
                                      </tr>
                                      <tr>
                                        <td height="20">
                                      </tr>
                                      </tbody>
                                    </table>
                                  </td>
                                  <td width="2%"></td>
                                  <td width="49%" align="center"
                                      style="background-color:#ffffff;border:#d4d4d4 1px solid">
                                    <table border="0" cellpadding="0" cellspacing="0" width="100%"
                                           style="table-layout:fixed">
                                      <tbody>
                                      <tr>
                                        <td align="center">
                                          <strong style="display:inline-block; color: #ee9336; font-size: 50px;">
                                            12
                                          </strong>
                                        </td>
                                      </tr>
                                      <tr>
                                        <td style="font-size:14px;color:#212121;line-height:18px;"
                                            align="center" height="30">Lỗ hổng cấp độ
                                        </td>
                                      </tr>
                                      <tr>
                                        <td height="10"></td>
                                      </tr>
                                      <tr>
                                        <td style="font-size:20px;color:#212121;line-height:18px;"
                                            align="center"><b>Cao</b>
                                        </td>
                                      </tr>
                                      <tr>
                                        <td height="20"></td>
                                      </tr>
                                      </tbody>
                                    </table>
                                  </td>
                                  <td width="2%"></td>
                                </tr>
                                </tbody>
                              </table>
                            </td>
                          </tr>
                          <tr>
                            <td height="16"></td>
                          </tr>
                          <tr>
                            <td width="100%" style="font-size:14px;color:#202020;line-height:1.5;">
                              <table border="0" cellpadding="0" cellspacing="0" width="100%"
                                     style="table-layout:fixed">
                                <tbody>
                                <tr>
                                  <td width="2%"></td>
                                  <td width="32%" align="center"
                                      style="background-color:#ffffff;border:#d4d4d4 1px solid;">
                                    <table border="0" cellpadding="0" cellspacing="0" width="100%"
                                           style="table-layout:fixed;">
                                      <tbody>
                                      <tr>
                                        <td height="10"></td>
                                      </tr>
                                      <tr>
                                        <td style="font-weight:700;font-size:32px;color:#fdc431;line-height:40px"
                                            align="center">2
                                        </td>
                                      </tr>
                                      <tr>
                                        <td height="10"></td>
                                      </tr>
                                      <tr>
                                        <td style="font-size:14px;color:#212121;line-height:18px;"
                                            align="center" height="30">Lỗ hổng cấp độ
                                        </td>
                                      </tr>
                                      <tr>
                                        <td height="10"></td>
                                      </tr>
                                      <tr>
                                        <td style="font-size:20px;color:#212121;line-height:18px;"
                                            align="center"><b>Trung bình</b>
                                        </td>
                                      </tr>
                                      <tr>
                                        <td height="20"></td>
                                      </tr>
                                      </tbody>
                                    </table>
                                  </td>
                                  <td width="2%"></td>
                                  <td width="32%" align="center"
                                      style="background-color:#ffffff;border:#d4d4d4 1px solid;">
                                    <table border="0" cellpadding="0" cellspacing="0" width="100%"
                                           style="table-layout:fixed;">
                                      <tbody>
                                      <tr>
                                        <td height="10"></td>
                                      </tr>
                                      <tr>
                                        <td style="font-weight:700;font-size:32px;color:#4cae4c;line-height:40px"
                                            align="center">7
                                        </td>
                                      </tr>
                                      <tr>
                                        <td height="10"></td>
                                      </tr>
                                      <tr>
                                        <td style="font-size:14px;color:#212121;line-height:18px;"
                                            align="center" height="30">Lỗ hổng cấp độ
                                        </td>
                                      </tr>
                                      <tr>
                                        <td height="10"></td>
                                      </tr>
                                      <tr>
                                        <td style="font-size:20px;color:#212121;line-height:18px;"
                                            align="center"><b>Thấp</b>
                                        </td>
                                      </tr>
                                      <tr>
                                        <td height="20"></td>
                                      </tr>
                                      </tbody>
                                    </table>
                                  </td>
                                  <td width="2%"></td>
                                  <td width="32%" align="center"
                                      style="background-color:#ffffff;border:#d4d4d4 1px solid;">
                                    <table border="0" cellpadding="0" cellspacing="0" width="100%"
                                           style="table-layout:fixed;">
                                      <tbody>
                                      <tr>
                                        <td height="10"></td>
                                      </tr>
                                      <tr>
                                        <td style="font-weight:700;font-size:32px;color:#357abd;line-height:40px"
                                            align="center">18
                                        </td>
                                      </tr>
                                      <tr>
                                        <td height="10"></td>
                                      </tr>
                                      <tr>
                                        <td style="font-size:14px;color:#212121;line-height:18px;"
                                            align="center" height="30">Lỗ hổng để lộ
                                        </td>
                                      </tr>
                                      <tr>
                                        <td height="10"></td>
                                      </tr>
                                      <tr>
                                        <td style="font-size:20px;color:#212121;line-height:18px;"
                                            align="center"><b>Thông tin</b>
                                        </td>
                                      </tr>
                                      <tr>
                                        <td height="20"></td>
                                      </tr>
                                      </tbody>
                                    </table>
                                  </td>
                                  <td width="2%"></td>
                                </tr>
				<tr>
                            	  <td height="8"></td>
                          	</tr>
                                </tbody>
                              </table>
                            </td>
                          </tr>
                          <tr>
                            <td height="16"></td>
                          </tr>
                          <tr>
                            <td width="100%" style="font-size:14px;color:#202020;line-height:1.5;">
                              <table border="0" cellspacing="0" cellpadding="0" align="center"
                                     style="table-layout:fixed;">
                                <tbody>
                                <tr valign="middle">
                                  <td height="14" align="center" colspan="2">
                                <span style="font-size:14px;">
                                  <i>Kết quả rà quét được thực hiện lúc 00:00 12-10-2017</i>
                                </span>
                                  </td>
                                </tr>
                                </tbody>
                              </table>
                            </td>
                          </tr>
                          <tr>
                            <td height="16"></td>
                          </tr>
                          <tr>
                            <td style="font-size:13px;color:#202020;line-height:1.5;"
                                align="center" width="100%">
                              <table border="0" cellspacing="0" cellpadding="0" width="100%"
                                     style="table-layout:fixed;">
                                <tbody>
                                <tr>
                                  <td width="25%"></td>
                                  <td style="background-color:#00994D;color:#fcfcfc;">
                                      <table border="0" cellspacing="0" cellpadding="0" width="100%"
                                             style="table-layout:fixed;">
                                        <tbody>
                                        <tr>
                                          <td height="5"></td>
                                        </tr>
                                        <tr>
                                          <td width="100%" align="center">
                                            <a href="http://dantri.com.vn/" target="_blank"
                                               style="width:100%;text-decoration:none;color:#fcfcfc;line-height: 22px;display:block;font-size:18px;font-weight:bold;">
                                              Báo cáo chi tiết
                                            </a>
                                          </td>
                                        </tr>
                                        <tr>
                                          <td height="5"></td>
                                        </tr>
                                        </tbody>
                                      </table>
                                  </td>
                                  <td width="25%"></td>
                                </tr>
                                <tr>
                                  <td height="20"></td>
                                </tr>
                                </tbody>
                              </table>
                            </td>
                          </tr>
                          </tbody>
                        </table>
                      </td>
                      <td width="32"></td>
                    </tr>
                    </tbody>
                  </table>
                </td>
              </tr>

              <tr>
                <td>
                  <table width="100%" cellpadding="0" cellspacing="0" border="0"
                         style="table-layout:fixed;font-size:100%;font-weight:400;vertical-align:top;background:#FFFFFF;">
                    <tbody>
                    <tr>
                      <td height="20"></td>
                    </tr>
                    <tr>
                      <td align="center">
                        <table width="100%" cellpadding="0" cellspacing="0" border="0" align="center"
                               style="table-layout:fixed;font-size:14px;color:#202020;">
                          <tbody>
                          <tr>
                            <td align="center">
                              <em><span style="color:#666">Để được Tư vấn - Hỗ trợ - Khắc phục sự cố</span></em>
                            </td>
                          </tr>
                          <tr>
                            <td height="5"></td>
                          </tr>
                          <tr>
                            <td align="center">
                              <strong>Hãy liên hệ ngay với chúng tôi: +84 986.464.517</strong>
                            </td>
                          </tr>
                          <tr>
                            <td height="20"></td>
                          </tr>
                          <tr>
                            <td align="center">
                              Công ty CP An Toàn Thông Tin MVS
                            </td>
                          </tr>
                          <tr>
                            <td height="5"></td>
                          </tr>
                          <tr>
                            <td align="center">
                              Trụ sở chính: Tầng 9, 459 Đội Cấn, quận Ba Đình, thành phố Hà Nội.
                            </td>
                          </tr>
                          <tr>
                            <td height="5"></td>
                          </tr>
                          <tr>
                            <td align="center">
                              Chi nhánh: 66 Hoàng Ngân, quận Cầu Giấy, thành phố Hà Nội.
                            </td>
                          </tr>
                          <tr>
                            <td height="5"></td>
                          </tr>
                          <tr>
                            <td align="center">
                              Email:
                              <a href="mailto:info@securitybox.vn"
                                 style="font-size:100%;font-weight:400;vertical-align:top;color:#124ba2;"
                                 target="_blank">info@securitybox.vn</a>
                            </td>
                          </tr>
                          </tbody>
                        </table>
                      </td>
                    </tr>
                    <tr>
                      <td height="20"></td>
                    </tr>
                    </tbody>
                  </table>
                </td>
              </tr>
              </tbody>
            </table>
          </td>
        </tr>
        </tbody>
      </table>
    </td>
  </tr>
  </tbody>
</table>
           </body>
           </html>
        """)
