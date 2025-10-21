import { Card } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";
import { Copy, Plus, Trash2, Eye, EyeOff } from "lucide-react";
import { useState, useEffect } from "react";
import { useToast } from "@/hooks/use-toast";

interface ApiKeyData {
  id: string;
  name: string;
  key: string;
  created: string;
  lastUsed: string;
  requests: number;
  credits?: number;
}

export function APIKeyDashboard() {
  const [apiKeys, setApiKeys] = useState<ApiKeyData[]>([]);
  const [visibleKeys, setVisibleKeys] = useState<Set<string>>(new Set());
  const [newKeyName, setNewKeyName] = useState("");
  const [isGenerating, setIsGenerating] = useState(false);
  const [isLoading, setIsLoading] = useState(true);
  const { toast } = useToast();

  useEffect(() => {
    fetchApiKeys();
  }, []);

  const getAccessToken = () => {
    try {
      return localStorage.getItem('access_token');
    } catch {
      return null;
    }
  };

  const fetchApiKeys = async () => {
    try {
      const token = getAccessToken();
      const response = await fetch("/api/api-keys", {
        headers: token ? { Authorization: `Bearer ${token}` } : undefined,
      });
      if (response.status === 401) {
        throw new Error("Unauthorized");
      }
      if (!response.ok) throw new Error("Failed to fetch API keys");
      const data = await response.json();
      setApiKeys(data);
    } catch (error: any) {
      toast({
        title: "Error",
        description: error?.message === 'Unauthorized' ? "Please log in to view your API keys" : "Failed to load API keys",
        variant: "destructive",
      });
    } finally {
      setIsLoading(false);
    }
  };

  const toggleKeyVisibility = (id: string) => {
    const newVisible = new Set(visibleKeys);
    if (newVisible.has(id)) {
      newVisible.delete(id);
    } else {
      newVisible.add(id);
    }
    setVisibleKeys(newVisible);
  };

  const copyToClipboard = (key: string) => {
    navigator.clipboard.writeText(key);
    toast({
      title: "Copied!",
      description: "API key copied to clipboard",
    });
  };

  const generateNewKey = async () => {
    if (!newKeyName.trim()) {
      toast({
        title: "Error",
        description: "Please enter a name for your API key",
        variant: "destructive",
      });
      return;
    }

    setIsGenerating(true);
    try {
      const token = getAccessToken();
      const response = await fetch("/api/api-keys", {
        method: "POST",
        headers: { 
          "Content-Type": "application/json",
          ...(token ? { Authorization: `Bearer ${token}` } : {}),
        },
        body: JSON.stringify({ 
          name: newKeyName,
          userId: null
        }),
      });
      
      if (response.status === 401) {
        throw new Error("Unauthorized");
      }
      if (!response.ok) throw new Error("Failed to generate API key");
      
      const newKey = await response.json();
      setApiKeys([...apiKeys, newKey]);
      setNewKeyName("");
      toast({
        title: "Success!",
        description: "New API key generated",
      });
    } catch (error: any) {
      toast({
        title: "Error",
        description: error?.message === 'Unauthorized' ? "Please log in before generating an API key" : "Failed to generate API key",
        variant: "destructive",
      });
    } finally {
      setIsGenerating(false);
    }
  };

  const deleteKey = async (id: string) => {
    try {
      const token = getAccessToken();
      const response = await fetch(`/api/api-keys/${id}`, {
        method: "DELETE",
        headers: token ? { Authorization: `Bearer ${token}` } : undefined,
      });
      
      if (response.status === 401) {
        throw new Error("Unauthorized");
      }
      if (!response.ok) throw new Error("Failed to delete API key");
      
      setApiKeys(apiKeys.filter((key) => key.id !== id));
      toast({
        title: "Deleted",
        description: "API key has been revoked",
      });
    } catch (error: any) {
      toast({
        title: "Error",
        description: error?.message === 'Unauthorized' ? "Please log in before deleting an API key" : "Failed to delete API key",
        variant: "destructive",
      });
    }
  };

  const maskKey = (key: string) => {
    return key.substring(0, 12) + "•".repeat(20) + key.substring(key.length - 4);
  };

  return (
    <div className="space-y-8">
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-3xl font-bold">API Keys</h2>
          <p className="text-muted-foreground mt-2">
            Manage your BlockSub API keys
          </p>
        </div>
      </div>

      <Card className="p-8">
        <h3 className="text-lg font-semibold mb-4">Generate New API Key</h3>
        <div className="flex gap-4">
          <Input
            placeholder="API Key Name (e.g., Production Key)"
            value={newKeyName}
            onChange={(e) => setNewKeyName(e.target.value)}
            data-testid="input-api-key-name"
            className="flex-1"
          />
          <Button
            onClick={generateNewKey}
            disabled={isGenerating}
            data-testid="button-generate-key"
          >
            <Plus className="w-4 h-4 mr-2" />
            {isGenerating ? "Generating..." : "Generate Key"}
          </Button>
        </div>
      </Card>

      <div className="space-y-4">
        {apiKeys.map((apiKey) => (
          <Card key={apiKey.id} className="p-6 hover-elevate transition-all" data-testid={`card-api-key-${apiKey.id}`}>
            <div className="flex items-start justify-between mb-4">
              <div>
                <div className="flex items-center gap-3 mb-2">
                  <h3 className="font-semibold text-lg">{apiKey.name}</h3>
                  <Badge variant="secondary">{apiKey.requests} requests</Badge>
                  {typeof apiKey.credits === 'number' && (
                    <Badge variant="outline">{apiKey.credits} credits</Badge>
                  )}
                </div>
                <p className="text-sm text-muted-foreground">
                  Created {apiKey.created} • Last used {apiKey.lastUsed}
                </p>
              </div>
              <Button
                variant="ghost"
                size="icon"
                onClick={() => deleteKey(apiKey.id)}
                data-testid={`button-delete-${apiKey.id}`}
              >
                <Trash2 className="w-4 h-4 text-destructive" />
              </Button>
            </div>

            <div className="flex items-center gap-2 bg-muted/50 p-4 rounded-md">
              <code className="flex-1 font-mono text-sm">
                {visibleKeys.has(apiKey.id) ? apiKey.key : maskKey(apiKey.key)}
              </code>
              <Button
                variant="ghost"
                size="icon"
                onClick={() => toggleKeyVisibility(apiKey.id)}
                data-testid={`button-toggle-visibility-${apiKey.id}`}
              >
                {visibleKeys.has(apiKey.id) ? (
                  <EyeOff className="w-4 h-4" />
                ) : (
                  <Eye className="w-4 h-4" />
                )}
              </Button>
              <Button
                variant="ghost"
                size="icon"
                onClick={() => copyToClipboard(apiKey.key)}
                data-testid={`button-copy-${apiKey.id}`}
              >
                <Copy className="w-4 h-4" />
              </Button>
            </div>
          </Card>
        ))}
      </div>
    </div>
  );
}
