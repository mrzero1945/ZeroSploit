package com.zerosploit.ui;

import android.app.Activity;
import android.os.Build;
import android.os.Bundle;
import android.view.View;
import android.view.ViewGroup;
import android.view.WindowInsets;
import android.widget.FrameLayout;
import android.widget.LinearLayout;

import com.zerosploit.core.Engine;
import com.zerosploit.core.ScanService;

/**
 * Root activity. Owns the engine lifecycle, the foreground scan service and a
 * five-tab shell. Screens are plain Views swapped into a container, so the
 * iOS-style navigation is done by pushing a new screen rather than by Android's
 * fragment/fragment-transition machinery.
 */
public class MainActivity extends Activity {

    private static final String[] TAB_LABELS = {"Network", "Target", "Modules", "Sessions", "Logs"};
    private static final String[] TAB_ICONS = {"network", "target", "modules", "sessions", "logs"};

    private FrameLayout container;
    private LinearLayout tabBar;
    private int currentTab;
    private Screen[] screens = new Screen[5];

    /** Detail screen pushed over a tab root, or null when a tab is showing. */
    private Screen pushed;

    /** A screen is a View that can be shown, re-rendered and torn down. */
    public interface Screen {
        View view();

        default void onShown() {}

        default void onHidden() {}

        default void onTabSelected() {}
    }

    @Override
    protected void onCreate(Bundle saved) {
        super.onCreate(saved);
        Design.bind(this);
        Engine.get().init(this);
        applyEdgeToEdge();

        LinearLayout root = new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);
        root.setBackgroundColor(Design.BG);

        View statusSpacer = new View(this);
        root.addView(statusSpacer, new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, Design.dp(this, 20)));
        statusSpacer.setTag("status_spacer");

        container = new FrameLayout(this);
        container.setBackgroundColor(Design.BG);
        root.addView(container, new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, 0, 1f));

        tabBar = Widgets.tabBar(this, TAB_LABELS, iconRes(), 0, this::selectTab);
        root.addView(tabBar, new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, Design.dp(this, 56)));

        View homeIndicator = new View(this);
        homeIndicator.setBackground(Widgets.round(Design.TEXT_3, Design.dp(this, 3)));
        LinearLayout.LayoutParams hip = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, Design.dp(this, 4));
        hip.setMargins(Design.dp(this, 120), 0, Design.dp(this, 120), 0);
        homeIndicator.setLayoutParams(hip);
        root.addView(homeIndicator, new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.WRAP_CONTENT, Design.dp(this, 22)));

        setContentView(root);
        applyInsets(root, statusSpacer);

        screens[0] = new NetworkScreen(this);
        screens[1] = new TargetScreen(this);
        screens[2] = new ModulesScreen(this);
        screens[3] = new SessionsScreen(this);
        screens[4] = new LogsScreen(this);

        ScanService.start(this);
        show(0, true);
    }

    private int[] iconRes() {
        int[] r = new int[TAB_ICONS.length];
        for (int i = 0; i < TAB_ICONS.length; i++) r[i] = Design.tabIcon(TAB_ICONS[i]);
        return r;
    }

    private void selectTab(int index) {
        if (pushed != null) dismissPushed();
        if (index == currentTab) {
            screens[index].onTabSelected();
            return;
        }
        show(index, false);
    }

    private void show(int index, boolean initial) {
        Screen prev = screens[currentTab];
        if (!initial) {
            prev.onHidden();
            container.removeView(prev.view());
        }
        currentTab = index;
        container.addView(screens[index].view(), new FrameLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.MATCH_PARENT));
        screens[index].onShown();
        // Rebuild the tab bar so the selected tint moves.
        ViewGroup parent = (ViewGroup) tabBar.getParent();
        int idx = parent.indexOfChild(tabBar);
        parent.removeViewAt(idx);
        tabBar = Widgets.tabBar(this, TAB_LABELS, iconRes(), index, this::selectTab);
        parent.addView(tabBar, idx, new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, Design.dp(this, 56)));
    }

    /**
     * Pushes a detail screen over the current tab.
     *
     * <p>The screen's {@code onShown()} runs here as well as for tab roots:
     * a detail screen subscribes to engine events in {@code onShown()} and
     * unsubscribes in {@code onHidden()}, so skipping the call left modules
     * completely inert until the tab was re-selected. The tab bar is hidden
     * because detail screens draw their own navigation bar with a Back control.
     */
    public void push(Screen detail) {
        if (pushed != null) return;   // already one level deep; ignore re-entry
        screens[currentTab].onHidden();
        container.removeAllViews();
        container.addView(detail.view(), new FrameLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.MATCH_PARENT));
        tabBar.setVisibility(View.GONE);
        pushed = detail;
        detail.onShown();
    }

    /** Returns from the pushed detail screen to the current tab. */
    public void pop() {
        if (pushed == null) return;
        dismissPushed();
        screens[currentTab].onShown();
    }

    private void dismissPushed() {
        if (pushed == null) return;
        pushed.onHidden();
        container.removeAllViews();
        pushed = null;
        tabBar.setVisibility(View.VISIBLE);
        container.addView(screens[currentTab].view(), new FrameLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.MATCH_PARENT));
    }

    @Override
    public void onBackPressed() {
        if (pushed != null) {
            pop();
            return;
        }
        super.onBackPressed();
    }

    private void applyEdgeToEdge() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            getWindow().setDecorFitsSystemWindows(false);
        }
    }

    private void applyInsets(LinearLayout root, View statusSpacer) {
        View decor = getWindow().getDecorView();
        decor.setOnApplyWindowInsetsListener((v, insets) -> {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                android.graphics.Insets bars = insets.getInsets(WindowInsets.Type.systemBars());
                statusSpacer.setLayoutParams(new LinearLayout.LayoutParams(
                        ViewGroup.LayoutParams.MATCH_PARENT,
                        Design.dp(MainActivity.this, 20) + bars.top));
                root.setPadding(0, 0, 0, bars.bottom);
            }
            return insets;
        });
    }

    @Override
    protected void onResume() {
        super.onResume();
        Engine.get().init(this);
        if (currentTab < screens.length && screens[currentTab] != null) {
            screens[currentTab].onTabSelected();
        }
    }

    @Override
    protected void onDestroy() {
        ScanService.stop(this);
        super.onDestroy();
    }
}
