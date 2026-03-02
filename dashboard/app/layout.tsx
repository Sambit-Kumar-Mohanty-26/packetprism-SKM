import "./globals.css";

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en">
      <body>
        <header className="site-header">PacketPrism Enterprise</header>
        <main className="site-main">{children}</main>
        <footer className="site-footer">© PacketPrism • Network Intelligence Platform</footer>
      </body>
    </html>
  );
}
