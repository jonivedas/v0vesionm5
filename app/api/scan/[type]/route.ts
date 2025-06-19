import { type NextRequest, NextResponse } from "next/server"

// VirusTotal API configuration
const VIRUSTOTAL_API_KEY =
  process.env.VIRUSTOTAL_API_KEY || "047673d4aa55dfb43497a72b4f70d126fc38b9bac2a4abaeace83275ea370699"
const VIRUSTOTAL_BASE_URL = "https://www.virustotal.com/vtapi/v2"

// Helper function to call VirusTotal API
async function callVirusTotalAPI(endpoint: string, params: any, method = "GET") {
  const url = `${VIRUSTOTAL_BASE_URL}${endpoint}`

  try {
    let response
    if (method === "POST") {
      const formData = new FormData()
      Object.keys(params).forEach((key) => {
        formData.append(key, params[key])
      })

      response = await fetch(url, {
        method: "POST",
        body: formData,
      })
    } else {
      const searchParams = new URLSearchParams(params)
      response = await fetch(`${url}?${searchParams}`)
    }

    if (!response.ok) {
      throw new Error(`VirusTotal API error: ${response.status}`)
    }

    return await response.json()
  } catch (error) {
    console.error("VirusTotal API call failed:", error)
    throw error
  }
}

// Helper function to wait for scan completion
async function waitForScanCompletion(resource: string, scanType: string, maxAttempts = 10) {
  for (let attempt = 0; attempt < maxAttempts; attempt++) {
    await new Promise((resolve) => setTimeout(resolve, 2000)) // Wait 2 seconds

    try {
      const reportParams = {
        apikey: VIRUSTOTAL_API_KEY,
        resource: resource,
      }

      const endpoint = scanType === "url" ? "/url/report" : "/file/report"
      const report = await callVirusTotalAPI(endpoint, reportParams)

      if (report.response_code === 1) {
        return report
      }
    } catch (error) {
      console.log(`Attempt ${attempt + 1} failed, retrying...`)
    }
  }

  throw new Error("Scan timeout - please try again later")
}

export async function POST(request: NextRequest, { params }: { params: { type: string } }) {
  try {
    const { type } = params

    // Validate scan type
    if (!["url", "file", "domain", "email", "ip"].includes(type)) {
      return NextResponse.json({ error: "Invalid scan type" }, { status: 400 })
    }

    const formData = await request.formData()
    let resource = ""

    if (type === "url") {
      resource = formData.get("url") as string
      if (!resource) {
        return NextResponse.json({ error: "No URL provided" }, { status: 400 })
      }

      // Ensure URL has protocol
      if (!resource.startsWith("http://") && !resource.startsWith("https://")) {
        resource = "https://" + resource
      }

      try {
        // First, submit URL for scanning
        const scanParams = {
          apikey: VIRUSTOTAL_API_KEY,
          url: resource,
        }

        await callVirusTotalAPI("/url/scan", scanParams, "POST")

        // Wait a moment then get the report
        await new Promise((resolve) => setTimeout(resolve, 3000))

        // Get the report
        const reportParams = {
          apikey: VIRUSTOTAL_API_KEY,
          resource: resource,
        }

        const report = await callVirusTotalAPI("/url/report", reportParams)

        if (report.response_code === 0) {
          return NextResponse.json(
            {
              error: "URL not found in VirusTotal database. Please try again in a few moments.",
              resource: resource,
            },
            { status: 404 },
          )
        }

        return NextResponse.json(report)
      } catch (error) {
        console.error("URL scan error:", error)
        return NextResponse.json(
          {
            error: "Failed to scan URL with VirusTotal API",
            details: error instanceof Error ? error.message : "Unknown error",
          },
          { status: 500 },
        )
      }
    } else if (type === "file") {
      const file = formData.get("file") as File
      if (!file) {
        return NextResponse.json({ error: "No file provided" }, { status: 400 })
      }

      // Validate file size (VirusTotal limit is 32MB for free API)
      if (file.size > 32 * 1024 * 1024) {
        return NextResponse.json({ error: "File too large. Maximum size is 32MB." }, { status: 400 })
      }

      try {
        // Submit file for scanning
        const fileBuffer = await file.arrayBuffer()
        const fileBlob = new Blob([fileBuffer])

        const scanFormData = new FormData()
        scanFormData.append("apikey", VIRUSTOTAL_API_KEY)
        scanFormData.append("file", fileBlob, file.name)

        const scanResponse = await fetch(`${VIRUSTOTAL_BASE_URL}/file/scan`, {
          method: "POST",
          body: scanFormData,
        })

        const scanResult = await scanResponse.json()

        if (!scanResponse.ok || scanResult.response_code !== 1) {
          throw new Error("Failed to submit file for scanning")
        }

        // Wait for scan completion and get report
        const report = await waitForScanCompletion(scanResult.resource, "file")

        return NextResponse.json(report)
      } catch (error) {
        console.error("File scan error:", error)
        return NextResponse.json(
          {
            error: "Failed to scan file with VirusTotal API",
            details: error instanceof Error ? error.message : "Unknown error",
          },
          { status: 500 },
        )
      }
    } else if (type === "domain") {
      resource = formData.get("domain") as string
      if (!resource) {
        return NextResponse.json({ error: "No domain provided" }, { status: 400 })
      }

      try {
        const reportParams = {
          apikey: VIRUSTOTAL_API_KEY,
          domain: resource,
        }

        const report = await callVirusTotalAPI("/domain/report", reportParams)

        if (report.response_code === 0) {
          return NextResponse.json(
            {
              error: "Domain not found in VirusTotal database",
              resource: resource,
            },
            { status: 404 },
          )
        }

        return NextResponse.json(report)
      } catch (error) {
        console.error("Domain scan error:", error)
        return NextResponse.json(
          {
            error: "Failed to scan domain with VirusTotal API",
            details: error instanceof Error ? error.message : "Unknown error",
          },
          { status: 500 },
        )
      }
    } else if (type === "ip") {
      resource = formData.get("ip") as string
      if (!resource) {
        return NextResponse.json({ error: "No IP address provided" }, { status: 400 })
      }

      // Validate IP format
      const ipRegex = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/
      if (!ipRegex.test(resource)) {
        return NextResponse.json({ error: "Invalid IP address format" }, { status: 400 })
      }

      try {
        const reportParams = {
          apikey: VIRUSTOTAL_API_KEY,
          ip: resource,
        }

        const report = await callVirusTotalAPI("/ip-address/report", reportParams)

        if (report.response_code === 0) {
          return NextResponse.json(
            {
              error: "IP address not found in VirusTotal database",
              resource: resource,
            },
            { status: 404 },
          )
        }

        return NextResponse.json(report)
      } catch (error) {
        console.error("IP scan error:", error)
        return NextResponse.json(
          {
            error: "Failed to scan IP address with VirusTotal API",
            details: error instanceof Error ? error.message : "Unknown error",
          },
          { status: 500 },
        )
      }
    } else if (type === "email") {
      const email = formData.get("email") as string
      if (!email) {
        return NextResponse.json({ error: "No email provided" }, { status: 400 })
      }

      if (!email.includes("@")) {
        return NextResponse.json({ error: "Invalid email format" }, { status: 400 })
      }

      // Extract domain from email
      const domain = email.split("@")[1]

      try {
        const reportParams = {
          apikey: VIRUSTOTAL_API_KEY,
          domain: domain,
        }

        const report = await callVirusTotalAPI("/domain/report", reportParams)

        if (report.response_code === 0) {
          return NextResponse.json(
            {
              error: "Email domain not found in VirusTotal database",
              resource: email,
              domain: domain,
            },
            { status: 404 },
          )
        }

        // Add email-specific information
        report.email = email
        report.domain = domain

        return NextResponse.json(report)
      } catch (error) {
        console.error("Email scan error:", error)
        return NextResponse.json(
          {
            error: "Failed to scan email domain with VirusTotal API",
            details: error instanceof Error ? error.message : "Unknown error",
          },
          { status: 500 },
        )
      }
    }
  } catch (error) {
    console.error("General scan API error:", error)
    return NextResponse.json(
      {
        error: "Internal server error",
        details: error instanceof Error ? error.message : "Unknown error",
      },
      { status: 500 },
    )
  }
}

export async function GET() {
  return NextResponse.json({ error: "Method not allowed. Use POST to submit scans." }, { status: 405 })
}
