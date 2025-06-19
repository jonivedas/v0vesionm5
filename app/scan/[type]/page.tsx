"use client"

import { useState } from "react"
import { useParams, useRouter } from "next/navigation"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { Upload, Loader2, Globe, File, Server, Mail, MapPin } from "lucide-react"
import { useToast } from "@/hooks/use-toast"

const scanTypeConfig = {
  url: {
    title: "URL Scanner",
    description: "Enter a URL to scan for malware and threats",
    icon: Globe,
    placeholder: "https://example.com",
    inputType: "url",
  },
  file: {
    title: "File Scanner",
    description: "Upload a file to scan for malware",
    icon: File,
    placeholder: "Choose file to upload",
    inputType: "file",
  },
  domain: {
    title: "Domain Scanner",
    description: "Enter a domain to check its reputation",
    icon: Server,
    placeholder: "example.com",
    inputType: "text",
  },
  ip: {
    title: "IP Address Scanner",
    description: "Enter an IP address to analyze network details",
    icon: MapPin,
    placeholder: "8.8.8.8",
    inputType: "text",
  },
  email: {
    title: "Email Scanner",
    description: "Enter an email address to verify",
    icon: Mail,
    placeholder: "user@example.com",
    inputType: "email",
  },
}

export default function ScanPage() {
  const params = useParams()
  const router = useRouter()
  const { toast } = useToast()
  const [input, setInput] = useState("")
  const [file, setFile] = useState<File | null>(null)
  const [isScanning, setIsScanning] = useState(false)

  const scanType = params.type as string
  const config = scanTypeConfig[scanType as keyof typeof scanTypeConfig]

  if (!config) {
    return <div>Invalid scan type</div>
  }

  const IconComponent = config.icon

  const validateIP = (ip: string) => {
    const ipRegex = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/
    return ipRegex.test(ip)
  }

  const handleScan = async () => {
    // Validation
    if (scanType === "file" && !file) {
      toast({
        title: "Error",
        description: "Please select a file to scan",
        variant: "destructive",
      })
      return
    }

    if (scanType !== "file" && !input.trim()) {
      toast({
        title: "Error",
        description: `Please enter a ${scanType} to scan`,
        variant: "destructive",
      })
      return
    }

    // Additional validation
    if (scanType === "url" && !input.includes(".")) {
      toast({
        title: "Error",
        description: "Please enter a valid URL",
        variant: "destructive",
      })
      return
    }

    if (scanType === "email" && !input.includes("@")) {
      toast({
        title: "Error",
        description: "Please enter a valid email address",
        variant: "destructive",
      })
      return
    }

    if (scanType === "ip" && !validateIP(input.trim())) {
      toast({
        title: "Error",
        description: "Please enter a valid IP address (e.g., 8.8.8.8)",
        variant: "destructive",
      })
      return
    }

    setIsScanning(true)

    try {
      const formData = new FormData()

      if (scanType === "file" && file) {
        formData.append("file", file)
      } else {
        formData.append(scanType, input.trim())
      }

      console.log(`Starting ${scanType} scan...`)

      const response = await fetch(`/api/scan/${scanType}`, {
        method: "POST",
        body: formData,
      })

      const result = await response.json()

      if (!response.ok) {
        throw new Error(result.error || `HTTP ${response.status}`)
      }

      console.log("Scan completed successfully")

      // Navigate to report page with results
      const reportData = encodeURIComponent(JSON.stringify(result))
      router.push(`/report?data=${reportData}&type=${scanType}`)
    } catch (error) {
      console.error("Scan error:", error)
      toast({
        title: "Scan Failed",
        description: error instanceof Error ? error.message : "Unable to complete the scan. Please try again.",
        variant: "destructive",
      })
    } finally {
      setIsScanning(false)
    }
  }

  return (
    <div className="min-h-screen bg-background py-12">
      <div className="container mx-auto px-4 max-w-2xl">
        <Card>
          <CardHeader className="text-center">
            <div className="flex justify-center mb-4">
              <IconComponent className="h-12 w-12 text-primary" />
            </div>
            <CardTitle className="text-2xl">{config.title}</CardTitle>
            <CardDescription>{config.description}</CardDescription>
          </CardHeader>
          <CardContent className="space-y-6">
            {scanType === "file" ? (
              <div className="space-y-2">
                <Label htmlFor="file">Select File</Label>
                <div className="border-2 border-dashed border-muted-foreground/25 rounded-lg p-8 text-center">
                  <Upload className="h-8 w-8 mx-auto mb-4 text-muted-foreground" />
                  <Input
                    id="file"
                    type="file"
                    onChange={(e) => {
                      const selectedFile = e.target.files?.[0]
                      if (selectedFile) {
                        setFile(selectedFile)
                        setInput(selectedFile.name)
                      }
                    }}
                    className="hidden"
                  />
                  <Label htmlFor="file" className="cursor-pointer">
                    <Button variant="outline" asChild>
                      <span>Choose File</span>
                    </Button>
                  </Label>
                  {file && <p className="mt-2 text-sm text-muted-foreground">Selected: {file.name}</p>}
                </div>
              </div>
            ) : (
              <div className="space-y-2">
                <Label htmlFor="input">
                  {scanType === "url"
                    ? "URL"
                    : scanType === "domain"
                      ? "Domain"
                      : scanType === "ip"
                        ? "IP Address"
                        : "Email Address"}
                </Label>
                <Input
                  id="input"
                  type={config.inputType}
                  placeholder={config.placeholder}
                  value={input}
                  onChange={(e) => setInput(e.target.value)}
                />
                {scanType === "ip" && (
                  <p className="text-xs text-muted-foreground">Enter a valid IPv4 address (e.g., 8.8.8.8, 1.1.1.1)</p>
                )}
              </div>
            )}

            <Button onClick={handleScan} disabled={isScanning || (!input && !file)} className="w-full">
              {isScanning ? (
                <>
                  <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                  Scanning...
                </>
              ) : (
                "Start Scan"
              )}
            </Button>
          </CardContent>
        </Card>
      </div>
    </div>
  )
}
