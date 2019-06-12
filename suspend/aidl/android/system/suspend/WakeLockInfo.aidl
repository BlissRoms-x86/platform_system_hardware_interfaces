/*
 * Copyright (C) 2019 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package android.system.suspend;


/**
 * Parcelable WakelockInfo - Representation of wake lock stats.
 *
 * @name:           Name of wake lock (Not guaranteed to be unique).
 * @pid:            Pid of process that aqcuired the wake lock.
 * @activeSince:    Time (in us) the wake lock was last activated.
 * @activeCount:    Number of times the wake lock was activated.
 * @maxTime:        Maximum time (in us) this wake lock has been continuously active.
 * @totalTime:      Total time (in us) this wake lock has been active.
 * @isActive:       Status of wake lock.
 *
 */
parcelable WakeLockInfo {
    @utf8InCpp String name;
    int pid;
    long activeSince;
    long activeCount;
    long lastChange;
    long maxTime;
    long totalTime;
    boolean isActive;
}
