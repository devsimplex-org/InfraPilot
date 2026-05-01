"use client";

import { useState, Fragment } from "react";
import { Dialog, Transition } from "@headlessui/react";
import { X, Box, Layers } from "lucide-react";
import { cn } from "@/lib/utils";
import { DeployWizard } from "@/components/DeployWizard";
import { StackDeployWizard } from "@/components/StackDeployWizard";

type DeployType = "container" | "stack";

export interface UnifiedDeployWizardProps {
  isOpen: boolean;
  onClose: () => void;
  onSuccess?: (id: string) => void;
}

export function UnifiedDeployWizard({ isOpen, onClose, onSuccess }: UnifiedDeployWizardProps) {
  const [selected, setSelected] = useState<DeployType | null>(null);

  const handleClose = () => {
    setSelected(null);
    onClose();
  };

  // Once type is selected, hand off to the appropriate wizard
  if (selected === "container") {
    return (
      <DeployWizard
        isOpen={isOpen}
        onClose={handleClose}
        onSuccess={onSuccess}
      />
    );
  }

  if (selected === "stack") {
    return (
      <StackDeployWizard
        isOpen={isOpen}
        onClose={handleClose}
        onSuccess={onSuccess}
      />
    );
  }

  // Type picker modal
  return (
    <Transition appear show={isOpen} as={Fragment}>
      <Dialog as="div" className="relative z-50" onClose={handleClose}>
        <Transition.Child
          as={Fragment}
          enter="ease-out duration-200" enterFrom="opacity-0" enterTo="opacity-100"
          leave="ease-in duration-150" leaveFrom="opacity-100" leaveTo="opacity-0"
        >
          <div className="fixed inset-0 bg-black/50" />
        </Transition.Child>

        <div className="fixed inset-0 flex items-center justify-center p-4">
          <Transition.Child
            as={Fragment}
            enter="ease-out duration-200" enterFrom="opacity-0 scale-95" enterTo="opacity-100 scale-100"
            leave="ease-in duration-150" leaveFrom="opacity-100 scale-100" leaveTo="opacity-0 scale-95"
          >
            <Dialog.Panel className="w-full max-w-md bg-white dark:bg-gray-900 rounded-xl shadow-xl">
              {/* Header */}
              <div className="flex items-center justify-between px-6 py-4 border-b border-gray-200 dark:border-gray-800">
                <Dialog.Title className="text-lg font-semibold text-gray-900 dark:text-white">
                  Deploy App
                </Dialog.Title>
                <button onClick={handleClose} className="text-gray-400 hover:text-gray-600 dark:hover:text-gray-300 transition-colors">
                  <X className="h-5 w-5" />
                </button>
              </div>

              {/* Type picker */}
              <div className="p-6 space-y-3">
                <p className="text-sm text-gray-500 dark:text-gray-400 mb-4">
                  Choose what you want to deploy:
                </p>

                <button
                  onClick={() => setSelected("container")}
                  className={cn(
                    "w-full flex items-start gap-4 p-4 rounded-xl border-2 transition-all text-left",
                    "border-gray-200 dark:border-gray-700 hover:border-primary-400 dark:hover:border-primary-500",
                    "hover:bg-primary-50 dark:hover:bg-primary-900/10 group"
                  )}
                >
                  <div className="p-2.5 rounded-lg bg-blue-100 dark:bg-blue-900/30 shrink-0 group-hover:bg-blue-200 dark:group-hover:bg-blue-900/50 transition-colors">
                    <Box className="h-5 w-5 text-blue-600 dark:text-blue-400" />
                  </div>
                  <div>
                    <p className="font-semibold text-gray-900 dark:text-white mb-0.5">Single Container</p>
                    <p className="text-sm text-gray-500 dark:text-gray-400">
                      Deploy a single Docker image. Ideal for individual services, APIs, or databases.
                    </p>
                  </div>
                </button>

                <button
                  onClick={() => setSelected("stack")}
                  className={cn(
                    "w-full flex items-start gap-4 p-4 rounded-xl border-2 transition-all text-left",
                    "border-gray-200 dark:border-gray-700 hover:border-primary-400 dark:hover:border-primary-500",
                    "hover:bg-primary-50 dark:hover:bg-primary-900/10 group"
                  )}
                >
                  <div className="p-2.5 rounded-lg bg-purple-100 dark:bg-purple-900/30 shrink-0 group-hover:bg-purple-200 dark:group-hover:bg-purple-900/50 transition-colors">
                    <Layers className="h-5 w-5 text-purple-600 dark:text-purple-400" />
                  </div>
                  <div>
                    <p className="font-semibold text-gray-900 dark:text-white mb-0.5">Docker Compose Stack</p>
                    <p className="text-sm text-gray-500 dark:text-gray-400">
                      Deploy multiple services together using a docker-compose.yml file.
                    </p>
                  </div>
                </button>
              </div>
            </Dialog.Panel>
          </Transition.Child>
        </div>
      </Dialog>
    </Transition>
  );
}
