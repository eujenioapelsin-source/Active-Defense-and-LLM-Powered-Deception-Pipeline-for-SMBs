import Console from "@/components/Console";

export default function Home() {
  return (
    <main className="min-h-screen p-8">
      <div className="max-w-6xl mx-auto">
        <header className="mb-8 border-b border-gray-800 pb-4 flex items-center justify-between">
          <div>
            <h1 className="text-3xl font-bold text-white flex items-center gap-2">
              <span className="text-blue-500">🛡️</span> Aegis Ledger
            </h1>
            <p className="text-gray-400 mt-1">Zero-Trust AI Data Integrity Pipeline</p>
          </div>
          <div className="text-sm px-3 py-1 bg-green-500/10 text-green-400 border border-green-500/20 rounded-full">
            System Online
          </div>
        </header>
        <Console />
      </div>
    </main>
  );
}