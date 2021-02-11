from burp import IBurpExtender
from burp import IScannerCheck
from burp import IScanIssue
from array import array
import sys


ssrfParamChecks = ["icon_url","url","uri","authorization_url","redirect_uri","redirect_url","redirect","referrer","origin","location","return_url","link","starturl","return","preview","previewurl","preview_url","loc","path","template","forward","goto","fetch","domain","check","dest","continue","next","site","html","callback","returnto","return_to","feed","host","to","out","view","show","open","viewurl","go","fromurl","from","from_url","fromuri","from_uri","redir","website","profileurl","profile_url","icon","avatar","targeturl","target_url","start","baseurl","oembed"]
lfiParamChecks = ["samplefile","file","html_file","src","source","upload","download","content","template","attachment","image","path","page","location","loc","include","dir","document","folder","root","pg","p","style","pdf","php_path","doc","icon","directory"]
fileExtensions = [".js", ".svg", ".jpeg", ".jpg", ".csv", ".xml", ".html", ".php", ".asp", ".aspx", ".png", ".ico", ".json", ".pdf", ".css", ".jsp", ".zip", ".gz", ".swf", ".woff"]
webRef = ["https", "http", "www"]

class BurpExtender(IBurpExtender, IScannerCheck):

	def registerExtenderCallbacks(self, callbacks):
		self._callbacks = callbacks
		self._helpers = callbacks.getHelpers()

		callbacks.setExtensionName("BurpParamFlagger")

		sys.stdout = callbacks.getStdout()
		sys.stderr = callbacks.getStderr()

		callbacks.registerScannerCheck(self)

	def _check_params(self, reqInfo):
		findings = {}
		params = reqInfo.getParameters()
		url = reqInfo.getUrl()
		for param in params:
			name = param.getName()
			value = param.getValue()

			if name.lower() in ssrfParamChecks or "_" + name.lower() in ssrfParamChecks or value.lower().startswith(tuple(webRef)):
				if "SSRF" not in findings.keys():
					findings["SSRF"] = []
				findings["SSRF"].append(name)

			if name.lower() in lfiParamChecks or "_" + name.lower() in lfiParamChecks or value.lower().endswith(tuple(fileExtensions)):
				if "LFI" not in findings.keys():
					findings["LFI"] = []
				findings["LFI"].append(name)

		return findings

	def doPassiveScan(self, baseRequestResponse):
		if self._callbacks.isInScope(self._helpers.analyzeRequest(baseRequestResponse).getUrl()):
			issues = []

			print(baseRequestResponse.getUrl())
			analyzed = self._helpers.analyzeRequest(baseRequestResponse.getHttpService(), baseRequestResponse.getRequest())
			matches = self._check_params(analyzed)

			if len(matches) == 0:
				return None

			print(matches)
			print(type(matches))
			print(matches.keys())
			req = baseRequestResponse.getRequest()
			
			for category, params in matches.items():
				for param in params:
					start = self._helpers.indexOf(req,
						param + "=", True, 0, len(req))
					offset = array('i', [0, 0])
					offset[0] = start
					offset[1] = start + len(param + "=")

					issues.append(ScanIssue(
						baseRequestResponse.getHttpService(),
						self._helpers.analyzeRequest(baseRequestResponse).getUrl(),
						[self._callbacks.applyMarkers(baseRequestResponse, [offset], None)],
						"Potential Target Parameter for {}".format(category),
						"The request has the parameter: <b>{}</b> <br><br>The name and/or value of this parameter indicates it may be a good place to test for {}.".format(param, category),
						"Information"))		
			return issues
		else:
			print("Out of Scope")
			print(self._helpers.analyzeRequest(baseRequestResponse).getUrl())


	def consolidateDuplicateIssues(self, existingIssue, newIssue):
		if (existingIssue.getIssueName() == newIssue.getIssueName()) and (existingIssue.getIssueDetail() == newIssue.getIssueDetail()) and (existingIssue.getUrl() == newIssue.getUrl()):
			print("Duplicate")
			print(existingIssue.getIssueDetail())
			return -1
		return 0

class ScanIssue (IScanIssue):
	def __init__(self, httpService, url, httpMessages, name, detail, severity):
		self._url = url
		self._name = name
		self._detail = detail
		self._severity = severity
		self._httpMessages = httpMessages
		self._httpService = httpService

	def getUrl(self):
		return self._url

	def getIssueName(self):
		return self._name

	def getIssueDetail(self):
		return self._detail

	def getSeverity(self):
		return self._severity

	def getConfidence(self):
		return "Certain"

	def getIssueBackground(self):
		return None

	def getRemediationBackground(self):
		return None

	def getRemediationDetail(self):
		return None

	def getIssueType(self):
		return 0

	def getHttpMessages(self):
		return self._httpMessages

	def getHttpService(self):
		return self._httpService
