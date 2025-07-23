async def _wait_for_splunk_dashboard_to_load(self, page, name):
    self.update_dashboard_status(name, "Waiting for panels...")
    logger.info(f"[LOG] Dashboard '{name}' - Waiting for dashboard panels to load.")
    
    # First, determine dashboard type
    is_studio = False
    try:
        await page.wait_for_selector("splunk-dashboard-view", timeout=5_000)
        is_studio = True
        logger.info(f"[LOG] Dashboard '{name}' - Detected Splunk Dashboard Studio")
    except Exception:
        logger.info(f"[LOG] Dashboard '{name}' - Detected Splunk Classic Dashboard")

    # Common element wait for both types
    try:
        await page.wait_for_selector("splunk-dashboard-view, div.dashboard-body", timeout=120_000)
    except Exception:
        logger.warning(f"[LOG] Dashboard '{name}' - Dashboard body selector not found within timeout.")
        self.update_dashboard_status(name, "Error: Dashboard body not found.")
        return

    # Studio-specific loading detection
    if is_studio:
        self.update_dashboard_status(name, "Studio: Waiting for panels to render...")
        logger.info(f"[LOG] Dashboard '{name}' - Waiting for Studio panels to render.")
        
        studio_script = """
        async () => {
            if (!window.require) {
                console.error('RequireJS not available');
                return false;
            }

            return new Promise((resolve, reject) => {
                try {
                    require(['splunkjs/mvc'], (mvc) => {
                        const components = mvc.Components.getInstance();
                        const vizIds = components.getIds().filter(id => {
                            const comp = components.get(id);
                            return comp && comp.on && comp.settings;
                        });

                        if (vizIds.length === 0) {
                            console.log('No visualizations found');
                            return resolve(true);
                        }

                        let loadedCount = 0;
                        const checkLoaded = () => {
                            if (++loadedCount === vizIds.length) {
                                console.log('All visualizations rendered');
                                resolve(true);
                            }
                        };

                        vizIds.forEach(id => {
                            const viz = components.get(id);
                            viz.on('dataRendered', checkLoaded);
                        });
                    });
                } catch (error) {
                    console.error('Error in studio script:', error);
                    reject(error);
                }
            });
        }
        """
        
        try:
            await page.wait_for_function(studio_script, timeout=120_000)
            logger.info(f"[LOG] Dashboard '{name}' - All Studio panels rendered.")
        except asyncio.TimeoutError as e:
            logger.warning(f"[LOG] Dashboard '{name}' - Timeout waiting for Studio panels: {e}")
            self.update_dashboard_status(name, "Warning: Timeout waiting for Studio panels.")
        except Exception as e:
            logger.warning(f"[LOG] Dashboard '{name}' - Error waiting for Studio panels: {e}")
            self.update_dashboard_status(name, "Error: Issue waiting for Studio panels.")
    
    # Classic dashboard loading detection
    else:
        try:
            # Initial export button check
            has_enabled_export_buttons = await page.evaluate("""() => {
                const exportButtons = document.querySelectorAll('.btn-pill.export');
                if (exportButtons.length === 0) return false;
                const disabledButtons = document.querySelectorAll('.btn-pill.export.disabled');
                return exportButtons.length > 0 && disabledButtons.length === 0;
            }""")
            
            if has_enabled_export_buttons:
                logger.info(f"[LOG] Dashboard '{name}' - Export buttons already enabled, waiting 5 seconds for potential input state...")
                self.update_dashboard_status(name, "Export enabled, waiting for input...")
                await asyncio.sleep(5)

            # Final export button state check
            self.update_dashboard_status(name, "Classic: Waiting for export buttons...")
            await page.wait_for_function("""() => {
                const exportButtons = document.querySelectorAll('.btn-pill.export');
                if (exportButtons.length === 0) return false;
                const disabledButtons = document.querySelectorAll('.btn-pill.export.disabled');
                const editExportButtons = document.querySelectorAll('a.btn.edit-export');
                return disabledButtons.length === 0 && editExportButtons.length > 0;
            }""", timeout=120_000)
            
            logger.info(f"[LOG] Dashboard '{name}' - Export buttons enabled and edit-export button present.")
        
        except asyncio.TimeoutError as e:
            logger.warning(f"[LOG] Dashboard '{name}' - Timeout during export button check: {e}")
            self.update_dashboard_status(name, "Warning: Timeout waiting for export buttons.")
        except Exception as e:
            logger.warning(f"[LOG] Dashboard '{name}' - Error during export button check: {e}")
            self.update_dashboard_status(name, "Error: Issue waiting for export buttons.")
    
    # Additional stabilization for both types
    self.update_dashboard_status(name, "Final stabilization...")
    try:
        await page.evaluate("""() => new Promise(resolve => {
            let lastChange = Date.now();
            const observer = new MutationObserver(() => lastChange = Date.now());
            observer.observe(document.body, { childList: true, subtree: true });
            const interval = setInterval(() => {
                if (Date.now() - lastChange > 2000) {
                    clearInterval(interval);
                    observer.disconnect();
                    resolve();
                }
            }, 500);
        })""")
    except Exception:
        logger.info(f"[LOG] Dashboard '{name}' - No additional changes detected during stabilization.")
    logger.info(f"[LOG] Dashboard '{name}' - Dashboard fully loaded.")