import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Button } from "@/components/ui/button"
import { Shield, Globe, File, Mail, Server, MapPin } from "lucide-react"
import Link from "next/link"

export default function HomePage() {
  const scanTypes = [
    {
      type: "url",
      title: "URL Scanner",
      description: "Scan suspicious URLs and websites",
      icon: Globe,
      color: "text-blue-500",
    },
    {
      type: "file",
      title: "File Scanner",
      description: "Upload and scan files for malware",
      icon: File,
      color: "text-green-500",
    },
    {
      type: "domain",
      title: "Domain Scanner",
      description: "Check domain reputation and safety",
      icon: Server,
      color: "text-purple-500",
    },
    {
      type: "ip",
      title: "IP Address Scanner",
      description: "Analyze IP addresses and network details",
      icon: MapPin,
      color: "text-red-500",
    },
    {
      type: "email",
      title: "Email Scanner",
      description: "Verify email addresses and domains",
      icon: Mail,
      color: "text-orange-500",
    },
  ]

  return (
    <div className="min-h-screen bg-background">
      <div className="container mx-auto px-4 py-12">
        {/* Hero Section */}
        <div className="text-center mb-16">
          <div className="flex justify-center mb-6">
            <Shield className="h-16 w-16 text-primary" />
          </div>
          <h1 className="text-4xl font-bold mb-4">Malware Scanner</h1>
          <p className="text-xl text-muted-foreground max-w-2xl mx-auto">
            Scan suspicious files, URLs, domains, IP addresses, or emails. Check before you click.
          </p>
        </div>

        {/* Scan Options */}
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 xl:grid-cols-5 gap-6 max-w-7xl mx-auto">
          {scanTypes.map((scan) => {
            const IconComponent = scan.icon
            return (
              <Card key={scan.type} className="hover:shadow-lg transition-shadow cursor-pointer">
                <CardHeader className="text-center">
                  <div className="flex justify-center mb-4">
                    <IconComponent className={`h-12 w-12 ${scan.color}`} />
                  </div>
                  <CardTitle className="text-lg">{scan.title}</CardTitle>
                  <CardDescription>{scan.description}</CardDescription>
                </CardHeader>
                <CardContent>
                  <Link href={`/scan/${scan.type}`}>
                    <Button className="w-full">Start Scan</Button>
                  </Link>
                </CardContent>
              </Card>
            )
          })}
        </div>

        {/* Features Section */}
        <div className="mt-20 text-center">
          <h2 className="text-2xl font-bold mb-8">Powered by VirusTotal</h2>
          <div className="grid grid-cols-1 md:grid-cols-3 gap-8 max-w-4xl mx-auto">
            <div className="text-center">
              <div className="bg-primary/10 rounded-full w-16 h-16 flex items-center justify-center mx-auto mb-4">
                <Shield className="h-8 w-8 text-primary" />
              </div>
              <h3 className="font-semibold mb-2">Real-time Protection</h3>
              <p className="text-sm text-muted-foreground">Get instant results from multiple antivirus engines</p>
            </div>
            <div className="text-center">
              <div className="bg-primary/10 rounded-full w-16 h-16 flex items-center justify-center mx-auto mb-4">
                <File className="h-8 w-8 text-primary" />
              </div>
              <h3 className="font-semibold mb-2">Detailed Reports</h3>
              <p className="text-sm text-muted-foreground">Comprehensive analysis with downloadable reports</p>
            </div>
            <div className="text-center">
              <div className="bg-primary/10 rounded-full w-16 h-16 flex items-center justify-center mx-auto mb-4">
                <MapPin className="h-8 w-8 text-primary" />
              </div>
              <h3 className="font-semibold mb-2">Network Analysis</h3>
              <p className="text-sm text-muted-foreground">Scan IPs, domains, URLs, files, and email addresses</p>
            </div>
          </div>
        </div>
      </div>
    </div>
  )
}
