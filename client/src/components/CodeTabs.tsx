import React, { useState } from 'react';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { Card } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Copy, Check } from 'lucide-react';
import { cn } from '@/lib/utils';

interface CopyCodeButtonProps {
  code: string;
  className?: string;
}

function CopyCodeButton({ code, className }: CopyCodeButtonProps) {
  const [copied, setCopied] = useState(false);

  const copyToClipboard = async () => {
    try {
      await navigator.clipboard.writeText(code);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    } catch (err) {
      console.error('Failed to copy code:', err);
    }
  };

  return (
    <Button
      variant="ghost"
      size="sm"
      onClick={copyToClipboard}
      className={cn(
        "absolute top-2 right-2 z-10 h-8 w-8 p-0 hover:bg-muted/80 transition-colors",
        className
      )}
      style={{ float: 'right' }}
    >
      {copied ? (
        <Check className="h-3 w-3 text-green-600" />
      ) : (
        <Copy className="h-3 w-3" />
      )}
    </Button>
  );
}

interface CodeTabsProps {
  group: string;
  curl: string;
  javascript: string;
  python: string;
  go: string;
  ruby: string;
  php: string;
  className?: string;
  title?: string;
}

export function CodeTabs({
  group,
  curl,
  javascript,
  python,
  go,
  ruby,
  php,
  className,
  title,
}: CodeTabsProps) {
  return (
    <div className={cn('space-y-3', className)}>
      {title && <h4 className="text-lg font-medium text-foreground">{title}</h4>}
      <Card className="p-0 overflow-hidden border-border bg-card shadow-sm">
        <Tabs defaultValue={`${group}-curl`}>
          <div className="border-b border-border bg-muted/30">
            <TabsList className="flex flex-wrap gap-1 bg-transparent p-2 h-auto">
              <TabsTrigger 
                value={`${group}-curl`} 
                className="text-xs px-3 py-1.5 data-[state=active]:bg-primary data-[state=active]:text-primary-foreground"
              >
                cURL
              </TabsTrigger>
              <TabsTrigger 
                value={`${group}-js`}
                className="text-xs px-3 py-1.5 data-[state=active]:bg-primary data-[state=active]:text-primary-foreground"
              >
                JavaScript
              </TabsTrigger>
              <TabsTrigger 
                value={`${group}-py`}
                className="text-xs px-3 py-1.5 data-[state=active]:bg-primary data-[state=active]:text-primary-foreground"
              >
                Python
              </TabsTrigger>
              <TabsTrigger 
                value={`${group}-go`}
                className="text-xs px-3 py-1.5 data-[state=active]:bg-primary data-[state=active]:text-primary-foreground"
              >
                Go
              </TabsTrigger>
              <TabsTrigger 
                value={`${group}-rb`}
                className="text-xs px-3 py-1.5 data-[state=active]:bg-primary data-[state=active]:text-primary-foreground"
              >
                Ruby
              </TabsTrigger>
              <TabsTrigger 
                value={`${group}-php`}
                className="text-xs px-3 py-1.5 data-[state=active]:bg-primary data-[state=active]:text-primary-foreground"
              >
                PHP
              </TabsTrigger>
            </TabsList>
          </div>
          <TabsContent value={`${group}-curl`} className="m-0">
            <div className="relative">
              <CopyCodeButton code={curl} />
              <pre className="overflow-auto text-xs p-4 bg-muted/20 text-muted-foreground font-mono">
                <code className="text-foreground">{curl}</code>
              </pre>
            </div>
          </TabsContent>
          <TabsContent value={`${group}-js`} className="m-0">
            <div className="relative">
              <CopyCodeButton code={javascript} />
              <pre className="overflow-auto text-xs p-4 bg-muted/20 text-muted-foreground font-mono">
                <code className="text-foreground">{javascript}</code>
              </pre>
            </div>
          </TabsContent>
          <TabsContent value={`${group}-py`} className="m-0">
            <div className="relative">
              <CopyCodeButton code={python} />
              <pre className="overflow-auto text-xs p-4 bg-muted/20 text-muted-foreground font-mono">
                <code className="text-foreground">{python}</code>
              </pre>
            </div>
          </TabsContent>
          <TabsContent value={`${group}-go`} className="m-0">
            <div className="relative">
              <CopyCodeButton code={go} />
              <pre className="overflow-auto text-xs p-4 bg-muted/20 text-muted-foreground font-mono">
                <code className="text-foreground">{go}</code>
              </pre>
            </div>
          </TabsContent>
          <TabsContent value={`${group}-rb`} className="m-0">
            <div className="relative">
              <CopyCodeButton code={ruby} />
              <pre className="overflow-auto text-xs p-4 bg-muted/20 text-muted-foreground font-mono">
                <code className="text-foreground">{ruby}</code>
              </pre>
            </div>
          </TabsContent>
          <TabsContent value={`${group}-php`} className="m-0">
            <div className="relative">
              <CopyCodeButton code={php} />
              <pre className="overflow-auto text-xs p-4 bg-muted/20 text-muted-foreground font-mono">
                <code className="text-foreground">{php}</code>
              </pre>
            </div>
          </TabsContent>
        </Tabs>
      </Card>
    </div>
  );
}