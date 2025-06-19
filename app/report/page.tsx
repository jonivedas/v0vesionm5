"use client"

import type React from "react"
import { useSearchParams } from "next/navigation"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Button } from "@/components/ui/button"
import { Badge } from "@/components/ui/badge"
import { Download, Shield, AlertTriangle, CheckCircle, XCircle, Info, MapPin, Building } from "lucide-react"
import { useToast } from "@/hooks/use-toast"

export default function ReportPage() {
  const searchParams = useSearchParams()
  const { toast } = useToast()

  const reportDataParam = searchParams.get("data")
  const scanType = searchParams.get("type")

  if (!reportDataParam) {
    return (
      <div className="min-h-screen bg-background py-12">
        <div className="container mx-auto px-4 text-center">
          <h1 className="text-2xl font-bold mb-4">No Report Data</h1>
          <p className="text-muted-foreground">No scan results to display.</p>
        </div>
      </div>
    )
  }

  let reportData
  try {
    reportData = JSON.parse(decodeURIComponent(reportDataParam))
  } catch (error) {
    return (
      <div className="min-h-screen bg-background py-12">
        <div className="container mx-auto px-4 text-center">
          <h1 className="text-2xl font-bold mb-4">Invalid Report Data</h1>
          <p className="text-muted-foreground">Unable to parse scan results.</p>
        </div>
      </div>
    )
  }

  // Handle VirusTotal API response structure
  const positives = reportData.detected_urls?.length || reportData.positives || 0
  const total = reportData.total || Object.keys(reportData.scans || {}).length || 0
  const scans = reportData.scans || {}
  const resource = reportData.resource || reportData.url || reportData.domain || reportData.ip || "Unknown"

  const getThreatLevel = (positives: number, total: number) => {
    if (total === 0) return { level: "Unknown", color: "text-gray-500", icon: Info }

    const ratio = positives / total
    if (ratio === 0) return { level: "Clean", color: "text-green-500", icon: CheckCircle }
    if (ratio < 0.05) return { level: "Low Risk", color: "text-yellow-500", icon: AlertTriangle }
    if (ratio < 0.15) return { level: "Medium Risk", color: "text-orange-500", icon: AlertTriangle }
    return { level: "High Risk", color: "text-red-500", icon: XCircle }
  }

  const threat = getThreatLevel(positives, total)
  const ThreatIcon = threat.icon

  const downloadReport = (format: "pdf" | "json") => {
    const data =
      format === "json"
        ? JSON.stringify(reportData, null, 2)
        : `VirusTotal Scan Report\n\nResource: ${resource}\nThreat Level: ${threat.level}\nDetections: ${positives}/${total}\nScan Date: ${reportData.scan_date || new Date().toISOString()}\n\nThis would be a proper PDF in production.`

    const blob = new Blob([data], {
      type: format === "json" ? "application/json" : "text/plain",
    })
    const url = URL.createObjectURL(blob)
    const a = document.createElement("a")
    a.href = url
    a.download = `virustotal-report-${Date.now()}.${format === "json" ? "json" : "txt"}`
    document.body.appendChild(a)
    a.click()
    document.body.removeChild(a)
    URL.revokeObjectURL(url)

    toast({
      title: "Download Started",
      description: `Report downloaded as ${format.toUpperCase()}`,
    })
  }

  // Get country flag emoji
  const getCountryFlag = (countryCode: string) => {
    if (!countryCode || countryCode.length !== 2) return "🌍"
    const codePoints = countryCode
      .toUpperCase()
      .split("")
      .map((char) => 127397 + char.charCodeAt(0))
    return String.fromCodePoint(...codePoints)
  }

  return (
    <div className="min-h-screen bg-background py-12">
      <div className="container mx-auto px-4 max-w-4xl">
        {/* Header */}
        <div className="text-center mb-8">
          <div className="flex justify-center mb-4">
            <Shield className="h-12 w-12 text-primary" />
          </div>
          <h1 className="text-3xl font-bold mb-2">VirusTotal Scan Report</h1>
          <p className="text-muted-foreground break-all">Scanned: {resource}</p>
        </div>

        {/* Threat Level */}
        <Card className="mb-8">
          <CardHeader className="text-center">
            <div className="flex justify-center mb-4">
              <ThreatIcon className={`h-16 w-16 ${threat.color}`} />
            </div>
            <CardTitle className={`text-2xl ${threat.color}`}>{threat.level}</CardTitle>
            <CardDescription>
              {scanType === "ip" && reportData.detected_urls ? (
                <>{reportData.detected_urls.length} detected malicious URLs associated with this IP</>
              ) : total > 0 ? (
                <>
                  {positives} of {total} security vendors flagged this as malicious
                </>
              ) : (
                "No scan data available"
              )}
            </CardDescription>
          </CardHeader>
        </Card>

        {/* IP Address Specific Information */}
        {scanType === "ip" && (
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6 mb-8">
            <Card>
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <MapPin className="h-5 w-5" />
                  Location Information
                </CardTitle>
              </CardHeader>
              <CardContent className="space-y-4">
                {reportData.country && (
                  <div>
                    <Label className="font-semibold">Country</Label>
                    <p className="text-sm text-muted-foreground flex items-center gap-2">
                      <span className="text-lg">{getCountryFlag(reportData.country)}</span>
                      {reportData.country}
                    </p>
                  </div>
                )}
                {reportData.as_owner && (
                  <div>
                    <Label className="font-semibold">AS Owner</Label>
                    <p className="text-sm text-muted-foreground">{reportData.as_owner}</p>
                  </div>
                )}
                {reportData.asn && (
                  <div>
                    <Label className="font-semibold">ASN</Label>
                    <p className="text-sm text-muted-foreground">AS{reportData.asn}</p>
                  </div>
                )}
                {reportData.network && (
                  <div>
                    <Label className="font-semibold">Network</Label>
                    <p className="text-sm text-muted-foreground">{reportData.network}</p>
                  </div>
                )}
              </CardContent>
            </Card>

            <Card>
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <Building className="h-5 w-5" />
                  Network Details
                </CardTitle>
              </CardHeader>
              <CardContent className="space-y-4">
                {reportData.detected_urls && (
                  <div>
                    <Label className="font-semibold">Detected URLs</Label>
                    <p className="text-sm text-muted-foreground">{reportData.detected_urls.length} malicious URLs</p>
                  </div>
                )}
                {reportData.detected_downloaded_samples && (
                  <div>
                    <Label className="font-semibold">Detected Samples</Label>
                    <p className="text-sm text-muted-foreground">
                      {reportData.detected_downloaded_samples.length} malicious samples
                    </p>
                  </div>
                )}
                {reportData.undetected_downloaded_samples && (
                  <div>
                    <Label className="font-semibold">Clean Samples</Label>
                    <p className="text-sm text-muted-foreground">
                      {reportData.undetected_downloaded_samples.length} clean samples
                    </p>
                  </div>
                )}
                {reportData.detected_communicating_samples && (
                  <div>
                    <Label className="font-semibold">Communicating Samples</Label>
                    <p className="text-sm text-muted-foreground">
                      {reportData.detected_communicating_samples.length} detected samples
                    </p>
                  </div>
                )}
              </CardContent>
            </Card>
          </div>
        )}

        {/* Download Buttons */}
        <div className="flex justify-center gap-4 mb-8">
          <Button onClick={() => downloadReport("json")} variant="outline">
            <Download className="mr-2 h-4 w-4" />
            Download JSON
          </Button>
          <Button onClick={() => downloadReport("pdf")} variant="outline">
            <Download className="mr-2 h-4 w-4" />
            Download Report
          </Button>
        </div>

        {/* Detailed Information */}
        <div className="grid grid-cols-1 md:grid-cols-2 gap-6 mb-8">
          <Card>
            <CardHeader>
              <CardTitle>Scan Details</CardTitle>
            </CardHeader>
            <CardContent className="space-y-4">
              <div>
                <Label className="font-semibold">Resource</Label>
                <p className="text-sm text-muted-foreground break-all">{resource}</p>
              </div>
              {reportData.scan_date && (
                <div>
                  <Label className="font-semibold">Last Analysis Date</Label>
                  <p className="text-sm text-muted-foreground">{new Date(reportData.scan_date).toLocaleString()}</p>
                </div>
              )}
              {reportData.permalink && (
                <div>
                  <Label className="font-semibold">VirusTotal Link</Label>
                  <a
                    href={reportData.permalink}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="text-sm text-blue-500 hover:underline break-all"
                  >
                    View on VirusTotal
                  </a>
                </div>
              )}
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle>Technical Details</CardTitle>
            </CardHeader>
            <CardContent className="space-y-4">
              {reportData.filescan_id && (
                <div>
                  <Label className="font-semibold">File Scan ID</Label>
                  <p className="text-sm text-muted-foreground">{reportData.filescan_id}</p>
                </div>
              )}
              {reportData.md5 && (
                <div>
                  <Label className="font-semibold">MD5 Hash</Label>
                  <p className="text-sm text-muted-foreground font-mono">{reportData.md5}</p>
                </div>
              )}
              {reportData.sha1 && (
                <div>
                  <Label className="font-semibold">SHA1 Hash</Label>
                  <p className="text-sm text-muted-foreground font-mono">{reportData.sha1}</p>
                </div>
              )}
              {reportData.sha256 && (
                <div>
                  <Label className="font-semibold">SHA256 Hash</Label>
                  <p className="text-sm text-muted-foreground font-mono break-all">{reportData.sha256}</p>
                </div>
              )}
            </CardContent>
          </Card>
        </div>

        {/* Detected URLs for IP scans */}
        {scanType === "ip" && reportData.detected_urls && reportData.detected_urls.length > 0 && (
          <Card className="mb-8">
            <CardHeader>
              <CardTitle>Detected Malicious URLs</CardTitle>
              <CardDescription>URLs hosted on this IP address that were flagged as malicious</CardDescription>
            </CardHeader>
            <CardContent>
              <div className="space-y-4 max-h-96 overflow-y-auto">
                {reportData.detected_urls.slice(0, 10).map((urlData: any, index: number) => (
                  <div key={index} className="flex items-center justify-between p-4 border rounded-lg">
                    <div className="flex-1">
                      <div className="font-medium break-all">{urlData.url}</div>
                      <div className="text-sm text-muted-foreground">
                        Detected: {urlData.positives}/{urlData.total} engines
                      </div>
                    </div>
                    <Badge variant="destructive">Malicious</Badge>
                  </div>
                ))}
                {reportData.detected_urls.length > 10 && (
                  <p className="text-sm text-muted-foreground text-center">
                    ... and {reportData.detected_urls.length - 10} more detected URLs
                  </p>
                )}
              </div>
            </CardContent>
          </Card>
        )}

        {/* Security Vendor Results */}
        {Object.keys(scans).length > 0 && (
          <Card>
            <CardHeader>
              <CardTitle>Security Vendor Results</CardTitle>
              <CardDescription>Results from {total} security vendors</CardDescription>
            </CardHeader>
            <CardContent>
              <div className="space-y-4">
                {Object.entries(scans).map(([vendor, result]: [string, any]) => (
                  <div key={vendor} className="flex items-center justify-between p-4 border rounded-lg">
                    <div className="flex items-center space-x-3">
                      <div className="font-medium">{vendor}</div>
                      <Badge variant={result.detected ? "destructive" : "secondary"}>
                        {result.detected ? "Detected" : "Clean"}
                      </Badge>
                    </div>
                    <div className="text-right text-sm text-muted-foreground">
                      {result.detected && result.result && (
                        <div className="text-red-500 font-medium">{result.result}</div>
                      )}
                      {result.version && <div>v{result.version}</div>}
                      {result.update && <div>Updated: {result.update}</div>}
                    </div>
                  </div>
                ))}
              </div>
            </CardContent>
          </Card>
        )}

        {/* No Results Message */}
        {Object.keys(scans).length === 0 && (!reportData.detected_urls || reportData.detected_urls.length === 0) && (
          <Card>
            <CardHeader>
              <CardTitle>No Detailed Results</CardTitle>
              <CardDescription>
                This resource may not have been scanned yet or detailed results are not available.
              </CardDescription>
            </CardHeader>
          </Card>
        )}
      </div>
    </div>
  )
}

function Label({ children, className = "" }: { children: React.ReactNode; className?: string }) {
  return <div className={`text-sm font-medium ${className}`}>{children}</div>
}
