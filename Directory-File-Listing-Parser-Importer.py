"""
Name:           Directory and File Listing Parser and Burp Site Map Importer
Version:        1.0
Date:           7/02/2013
Author:         Smeege
Contact:        SmeegeSec@gmail.com

Description:    This is a Burp Suite extension in Python to parse a directory and file listing text file of a web application.  
                Once the directories and files are parsed a list of URLs is generated based on a couple of parameters given by 
                the user.  After the list of URLs is generated the user can either copy the list and use as desired or choose
                to import the list into Burp's Target Site Map.  By importing the list a request will be made via each URL and
                a proper response will be checked for before adding the request/response pair to Burp's Target Site Map.
"""

from javax.swing import BorderFactory, ButtonGroup, JButton, JComboBox, \
JFileChooser, JFrame, JLabel, JOptionPane, JPanel, JRadioButton, JScrollPane, JTextArea, JTextField
from javax.swing.filechooser import FileNameExtensionFilter
from java.awt import BorderLayout, Dimension, Font, GridLayout
import os, shlex
from burp import IBurpExtender, IContextMenuFactory
from java.net import URL
from javax.swing import JMenuItem
from urllib2 import urlopen


class BurpExtender(IBurpExtender, IContextMenuFactory):
    # Implement IBurpExtender
    def registerExtenderCallbacks(self, callbacks):

        # Set extension name
        callbacks.setExtensionName("Directory Listing Parser for Burp Suite")

        # Callbacks object
        self._callbacks = callbacks

        # Helpers object
        self._helpers = callbacks.getHelpers()

        # Register a factory for custom context menu items
        callbacks.registerContextMenuFactory(self)

        return

    # Create a menu item if the appropriate section of the UI is selected
    def createMenuItems(self, invocation):
        menu = []

        # Which part of the interface the user selects
        ctx = invocation.getInvocationContext()

        # Message Viewer Req/Res, Site Map Table, and Proxy History will show menu item if selected by the user
        if ctx == 2 or ctx == 3 or  ctx == 4 or ctx == 5 or ctx == 6:
            menu.append(JMenuItem("Import Directory Listing", None, actionPerformed=lambda x, inv=invocation: self.openGUI(inv)))

        return menu if menu else None

    # Create and place GUI components on JFrame
    def openGUI(self, invocation):
        try:
            # Get values from request or response the extension is invoked from and prepopulate GUI values
            invMessage = invocation.getSelectedMessages()
            message = invMessage[0]
            originalHttpService = message.getHttpService()
            self.originalMsgProtocol = originalHttpService.getProtocol()
            self.originalMsgHost = originalHttpService.getHost()
            self.originalMsgPort = originalHttpService.getPort()
        except:
            self.originalMsgProtocol = ''
            self.originalMsgHost = ''
            self.originalMsgPort = ''

        try:
            self.cookies = self._callbacks.getCookieJarContents()
            self.cookie = ''
        except:
            pass

        self.SSL = 'http://'
        self.listType = ''
        self.parsedList = []

        # Set up main window (JFrame)
        self.window = JFrame("Directory Listing Parser for Burp Suite", preferredSize=(600, 475), windowClosing=self.closeUI)
        self.window.setDefaultCloseOperation(JFrame.DO_NOTHING_ON_CLOSE)
        emptyBorder = BorderFactory.createEmptyBorder(10, 10, 10, 10)
        self.window.contentPane.setBorder(emptyBorder)
        self.window.contentPane.layout = BorderLayout()

        # Main window title placed at the top of the main window with an invisible bottom border
        titlePanel = JPanel()
        titleBorder = BorderFactory.createEmptyBorder(0, 0, 10, 0)
        title = JLabel("Directory Listing Parser for Burp Suite", JLabel.CENTER)
        title.setBorder(titleBorder)
        title.setFont(Font("Default", Font.PLAIN, 18))
        titlePanel.add(title)
        self.window.contentPane.add("North", titlePanel)

        # Left panel for user input, consisting of hostname, directory prefix, ssl, port, type of listing, and file
        self.leftPanel = JPanel()
        self.leftPanel.layout = GridLayout(14, 1, 3, 3)
        hostnameLabel = JLabel("Hostname:")

        if self.originalMsgHost:
            self.hostnameTextField = JTextField(self.originalMsgHost.rstrip())
        else:
            self.hostnameTextField = JTextField('Hostname')

        dirPrefixLabel = JLabel("Full Directory Prefix (Windows):")
        self.dirPrefixField = JTextField('C:\\var\www\\')
        
        sslLabel = JLabel("SSL:")
        self.radioBtnSslEnabled = JRadioButton('Enabled (https)', actionPerformed=self.radioSsl)
        self.radioBtnSslDisabled = JRadioButton('Disabled (http)', actionPerformed=self.radioSsl)
        sslButtonGroup = ButtonGroup()
        sslButtonGroup.add(self.radioBtnSslEnabled)
        sslButtonGroup.add(self.radioBtnSslDisabled)
        
        if self.originalMsgProtocol == "https":
            self.radioBtnSslEnabled.setSelected(True)
        else:
            self.radioBtnSslDisabled.setSelected(True)
        
        portLabel = JLabel("Port:")

        if self.originalMsgPort:
            self.portTextField = JTextField(str(self.originalMsgPort).rstrip())
        else:
            self.portTextField = JTextField('80')

        osLabel = JLabel("Type of File Listing:")
        self.types = ('Windows \'dir /s\'', 'Linux \'ls -lR\'', 'Linux \'ls -R\'')
        self.comboListingType = JComboBox(self.types)
        uploadLabel = JLabel("Directory Listing File:")
        self.uploadTextField = JTextField('')
        uploadButton = JButton('Choose File', actionPerformed=self.chooseFile)

        self.leftPanel.add(hostnameLabel)
        self.leftPanel.add(self.hostnameTextField)
        self.leftPanel.add(dirPrefixLabel)
        self.leftPanel.add(self.dirPrefixField)
        self.leftPanel.add(sslLabel)
        self.leftPanel.add(self.radioBtnSslEnabled)
        self.leftPanel.add(self.radioBtnSslDisabled)
        self.leftPanel.add(portLabel)
        self.leftPanel.add(self.portTextField)
        self.leftPanel.add(osLabel)
        self.leftPanel.add(self.comboListingType)
        self.leftPanel.add(uploadLabel)
        self.leftPanel.add(self.uploadTextField)
        self.leftPanel.add(uploadButton)

        # Right panel consisting of a text area for the URL list
        self.UrlPanelLabel = JLabel("URL List:")
        self.textArea = JTextArea()
        self.textArea.setEditable(True)
        self.textArea.setFont(Font("Default", Font.PLAIN, 14))
        if self.cookies:
            self.textArea.append('Cookies Found:\n')
            for cookie in self.cookies:
                if cookie.getDomain() == self.originalMsgHost:
                    self.cookie += cookie.getName() + '=' + cookie.getValue() + '; '
                    self.textArea.append(cookie.getName() + '=' + cookie.getValue() + '\n')
        scrollArea = JScrollPane(self.textArea)
        scrollArea.setVerticalScrollBarPolicy(JScrollPane.VERTICAL_SCROLLBAR_ALWAYS)
        scrollArea.setPreferredSize(Dimension(400, 200))
        self.rightPanel = JPanel()
        self.rightPanel.setLayout(BorderLayout(3, 3))
        self.rightPanel.add(self.UrlPanelLabel, BorderLayout.NORTH)
        self.rightPanel.add(scrollArea, BorderLayout.CENTER)
        
        # Panel for the generate URL list and import URL list buttons
        generatePanel = JPanel()
        generatePanel.layout = BorderLayout(3, 3)
        generateButton = JButton('Generate URL List', actionPerformed=self.generateUrlList)
        importButton = JButton('Import URL List to Burp Site Map', actionPerformed=self.importList)
        generatePanel.add("North", generateButton)
        generatePanel.add("South", importButton)
        self.rightPanel.add("South", generatePanel)

        # Add the two main panels to the left and right sides
        self.window.contentPane.add("East", self.rightPanel)
        self.window.contentPane.add("West", self.leftPanel)

        # Create a panel to be used for the file chooser window
        self.uploadPanel = JPanel()
        
        self.window.pack()
        self.window.show()

    # JFileChooser and showDialog for the user to specify their directory listing input file
    def chooseFile(self, event):
        chooseFile = JFileChooser()
        filter = FileNameExtensionFilter("c files", ["c"])
        chooseFile.addChoosableFileFilter(filter)
        chooseFile.showDialog(self.uploadPanel, "Choose File")
        chosenFile = chooseFile.getSelectedFile()
        self.uploadTextField.text = str(chosenFile)

    # Set whether https is enabled.  Default is disabled (http)
    def radioSsl(self, event):
        if self.radioBtnSslEnabled.isSelected():
            self.SSL = 'https://'
        else:
            self.SSL = 'http://'

    # Create a parser object and pass the user's specified options.  Retrieve the results and print them to a text area
    def generateUrlList(self, event):
        fileListingType = self.comboListingType.selectedIndex
        self.listType = self.types[fileListingType]
        urlsMade = 0
        if os.path.isfile(self.uploadTextField.text):
            parser = ListingParser()
            parser.parse(self.hostnameTextField.getText(), self.dirPrefixField.getText().rstrip(), self.SSL, self.portTextField.getText(), self.listType, self.uploadTextField.getText())
            self.parsedList = parser.returnList()
            self.textArea.setText('')
            for item in self.parsedList:
                self.textArea.append(item + '\n')

            urlsMade = str(len(self.parsedList))
            if self.parsedList and urlsMade:
                self.textArea.append('\n' + 'Total Directories Found: ' + str(parser.directoryCount))
                self.textArea.append('\n' + 'Total URLs Created: ' + urlsMade)
            else:
                self.textArea.append('Error occurred during parsing.\n')
                self.textArea.append('Please make sure the directory listing is a valid format and all input is correct.\n')
                self.textArea.append('E-mail SmeegeSec@gmail.com with errors or for further help.')
        else:
            JOptionPane.showMessageDialog(None, 'ERROR: File is not valid file or not found!')

    def closeUI(self, event):
        self.window.setVisible(False)
        self.window.dispose()

    # This is initiated by the user selecting the 'import to burp' button.  Checks each generated URL for a valid response and adds it to the site map
    def importList(self, event):
        if self.parsedList:
            urlsAdded = 0
            # Loop through each URL and check the response.  If the response code is less than 404, add to site map
            for item in self.parsedList:
                # Pass exception if urlopen returns an http error if the URL is not reachable
                try:
                    code = urlopen(item).code
                    if code < 404:
                        javaURL = URL(item)
                        newRequest = self._helpers.buildHttpRequest(javaURL)
                        stringNewRequest = self._helpers.bytesToString(newRequest).rstrip()
                        if self.cookie:
                            stringNewRequest += '\nCookie: ' + self.cookie.rstrip('; ') + '\r\n\r\n'
                            requestResponse = self._callbacks.makeHttpRequest(self._helpers.buildHttpService(str(javaURL.getHost()), int(javaURL.getPort()), javaURL.getProtocol() == "https"), stringNewRequest)
                        else:
                            requestResponse = self._callbacks.makeHttpRequest(self._helpers.buildHttpService(str(javaURL.getHost()), int(javaURL.getPort()), javaURL.getProtocol() == "https"), newRequest)
                        self._callbacks.addToSiteMap(requestResponse)
                        urlsAdded += 1
                except Exception, e:
                    print e
                    pass
            JOptionPane.showMessageDialog(None, str(urlsAdded) + " URL(s) added to Burp site map.")
        else:
            JOptionPane.showMessageDialog(None, "The list of URLs is empty.  Please generate a valid list to import.")


# Class to parse the directory listing file specified by the user
class ListingParser:
    def parse(self, hostname, prefix, ssl, port, listing, filename):
        self.fullUrlList = []
        self.directoryCount = 0
        if os.path.isfile(filename):
            filePosition = 0
            urlSuffix = ''
            # Check the user's selection from the list type drop down and parse accordingly
            if listing == 'Windows \'dir /s\'':
                f = open(filename, "r")
                lines = f.readlines()
                for line in lines:
                    # Windows directory files typically have two formats.  Conditional in place to detect which format and parse accordingly
                    try:
                        if 'Directory: ' in line:
                            filePosition = 5
                            directory = line.split('Directory: ', 1)[1]
                            self.directoryCount += 1
                        elif 'Directory of ' in line:
                            filePosition = 4
                            directory = line.split('Directory of ', 1)[1]
                            self.directoryCount += 1
                        # Using shlex to parse each line in the file, ignoring anything that is not a file
                        if filePosition > 0 and len(shlex.split(line)) > filePosition:
                                for num in range(filePosition, len(shlex.split(line))):
                                    urlSuffix += shlex.split(line)[num] + " "
                                if urlSuffix != ". " and urlSuffix != ".. " and 'logout' not in urlSuffix and 'logoff' not in urlSuffix and 'exit' not in urlSuffix and 'signout' not in urlSuffix:
                                    dirPrefix = directory.split(prefix)[1].rstrip().replace('\\', '/')
                                    if '.' in urlSuffix:
                                        fullUrl = (hostname + ':' + port + '/' + dirPrefix + '/' + urlSuffix).rstrip().replace('//', '/')
                                    else:
                                        fullUrl = (hostname + ':' + port + '/' + dirPrefix + '/' + urlSuffix).rstrip().replace('//', '/') + '/'
                                    self.fullUrlList.append(ssl + fullUrl)
                                urlSuffix = ''
                    except:
                        pass
            elif listing == 'Linux \'ls -lR\'':
                f = open(filename, "r")
                lines = f.readlines()
                directory = '/'
                parentDir = False
                suffix = ''
                for line in lines:
                    try:
                        if '.:' in line:
                            parentDir = True
                        elif '.' in line and ':\n' in line:
                            parentDir = False
                            directory = line[line.find('.') + 1 : line.find(':')]
                            self.directoryCount += 1
                        else:
                            if len(shlex.split(line)) and 'total ' not in line:
                                if parentDir:
                                    for num in range(8,len(shlex.split(line))):
                                        suffix += shlex.split(line)[num] + ' '
                                    if '.' in suffix:
                                        fullSuffix = directory + suffix.rstrip()
                                    else:
                                        fullSuffix = directory + suffix.rstrip() + '/'
                                    if 'logout' not in fullSuffix and 'logoff' not in fullSuffix and 'exit' not in fullSuffix and 'signout' not in fullSuffix:
                                        if prefix.rstrip() != 'C:\\var\www\\':
                                            fullUrl = ssl + hostname + ':' + port + '/' + prefix.rstrip() + fullSuffix
                                        else:
                                            fullUrl = ssl + hostname + ':' + port + fullSuffix
                                        self.fullUrlList.append(fullUrl)
                                else:
                                    for num in range(8, len(shlex.split(line))):
                                        suffix += shlex.split(line)[num] + ' '
                                    if '.' in suffix:
                                        fullSuffix = directory + '/' + suffix.rstrip()
                                    else:
                                        fullSuffix = directory + '/' + suffix.rstrip() + '/'
                                    if 'logout' not in fullSuffix and 'logoff' not in fullSuffix and 'exit' not in fullSuffix and 'signout' not in fullSuffix:
                                        if prefix.rstrip() != 'C:\\var\www\\':
                                            fullUrl = ssl + hostname + ':' + port + '/' + prefix.rstrip() + fullSuffix
                                        else:
                                            fullUrl = ssl + hostname + ':' + port + fullSuffix

                                        self.fullUrlList.append(fullUrl)
                                suffix = ''
                    except:
                        pass
            elif listing == 'Linux \'ls -R\'':
                f = open(filename, "r")
                lines = f.readlines()
                parentDir = False
                directory = '/'
                for line in lines:
                    try:
                        if '.:' in line:
                            parentDir = True
                        elif '.' in line and ':\n' in line:
                            parentDir = False
                            directory = line[line.find('.') + 1 : line.find(':')]
                            self.directoryCount += 1
                        else:
                            if len(shlex.split(line)) and 'total ' not in line:
                                if parentDir:
                                    suffix = shlex.split(line)
                                    for num in range(0, len(suffix)):
                                        if '.' in suffix[num]:
                                            if prefix.rstrip() != 'C:\\var\www\\':
                                                fullUrl = ssl + hostname + ':' + port + '/' + prefix.rstrip() + directory + suffix[num]
                                            else:
                                                fullUrl = ssl + hostname + ':' + port + directory + suffix[num]
                                        else:
                                            print suffix[num]
                                            if prefix.rstrip() != 'C:\\var\www\\':
                                                fullUrl = ssl + hostname + ':' + port + '/' + prefix.rstrip() + directory + suffix[num] + '/'
                                            else:
                                                fullUrl = ssl + hostname + ':' + port + directory + suffix[num] + '/'

                                        if 'logout' not in fullUrl and 'logoff' not in fullUrl and 'exit' not in fullUrl and 'signout' not in fullUrl:
                                            self.fullUrlList.append(fullUrl)
                                else:
                                    for num in range(0, len(shlex.split(line))):
                                        if prefix.rstrip() != 'C:\\var\www\\':
                                            fullUrl = ssl + hostname + ':' + port + '/' + prefix.rstrip() + directory + '/' + shlex.split(line)[num]
                                        else:
                                            fullUrl = ssl + hostname + ':' + port + directory + '/' + shlex.split(line)[num]
                                        if 'logout' not in fullUrl and 'logoff' not in fullUrl and 'exit' not in fullUrl and 'signout' not in fullUrl:
                                            self.fullUrlList.append(fullUrl)
                    except:
                        pass
            else:
                JOptionPane.showMessageDialog(None, 'ERROR: Invalid or no listing type specified')
        else:
            JOptionPane.showMessageDialog(None, 'ERROR: ' + filename + ' is not a valid file or was not found!')

        try:
            f.close()
        except:
            pass

    def returnList(self):
        return self.fullUrlList
